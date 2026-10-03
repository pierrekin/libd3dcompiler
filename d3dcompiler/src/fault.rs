//! Faults inside the DLLs. On Windows a caller can catch a crash inside a compiler with SEH and fail
//! only what it was doing. Here a caller registers a recovery point, a sigjmp_buf it set with
//! sigsetjmp, and a fault in a DLL or in this library's stand-ins jumps back to it. Every other fault
//! goes to the handler that was installed before, such as the host's crash reporter.

use crate::module::{describe, find_by_address, try_find_by_address};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;

unsafe extern "C" {
    fn siglongjmp(env: *mut c_void, value: i32) -> !;
}

const SIGNALS: [i32; 4] = [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE];

thread_local! {
    static RECOVERY: Cell<*mut c_void> = const { Cell::new(std::ptr::null_mut()) };
    // The last fault recovered from on this thread: its signal, where it happened, and the nearest
    // return address into a DLL on the stack then
    static LAST_FAULT: Cell<(i32, usize, usize)> = const { Cell::new((0, 0, 0)) };
}

static PREVIOUS: OnceLock<[libc::sigaction; 4]> = OnceLock::new();

/// Whether an address is in a loaded DLL or in this library, which runs the DLLs' imports
fn in_dll_code(addr: usize) -> bool {
    if try_find_by_address(addr).is_some() {
        return true;
    }
    unsafe {
        let (mut fault, mut own): (libc::Dl_info, libc::Dl_info) =
            (std::mem::zeroed(), std::mem::zeroed());
        libc::dladdr(addr as *const c_void, &mut fault) != 0
            && libc::dladdr(in_dll_code as *const c_void, &mut own) != 0
            && fault.dli_fbase == own.dli_fbase
    }
}

unsafe extern "C" fn handler(signal: i32, info: *mut libc::siginfo_t, context: *mut c_void) {
    let rip = unsafe {
        (*(context as *mut libc::ucontext_t)).uc_mcontext.gregs[libc::REG_RIP as usize] as usize
    };
    let rsp = unsafe {
        (*(context as *mut libc::ucontext_t)).uc_mcontext.gregs[libc::REG_RSP as usize] as usize
    };
    let recovery = RECOVERY.with(Cell::get);
    if !recovery.is_null() && in_dll_code(rip) {
        RECOVERY.with(|r| r.set(std::ptr::null_mut()));
        let caller = (0..512)
            .map(|i| unsafe { *((rsp + i * 8) as *const usize) })
            .find(|&a| try_find_by_address(a).is_some())
            .unwrap_or(0);
        LAST_FAULT.with(|f| f.set((signal, rip, caller)));
        unsafe { siglongjmp(recovery, 1) };
    }
    #[cfg(feature = "trace-imports")]
    report(signal, rip, context);
    let Some(previous) = PREVIOUS
        .get()
        .and_then(|p| SIGNALS.iter().position(|&s| s == signal).map(|i| p[i]))
    else {
        return;
    };
    unsafe {
        if previous.sa_flags & libc::SA_SIGINFO != 0 && previous.sa_sigaction > 1 {
            let previous_handler: unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut c_void) =
                std::mem::transmute(previous.sa_sigaction);
            previous_handler(signal, info, context);
        } else if previous.sa_sigaction > 1 {
            let previous_handler: unsafe extern "C" fn(i32) =
                std::mem::transmute(previous.sa_sigaction);
            previous_handler(signal);
        } else {
            // the default action, which the faulting instruction meets again once this returns
            libc::signal(signal, libc::SIG_DFL);
        }
    }
}

// In trace builds, a fault nothing recovers from names the DLL and offset it happened at, and the
// return addresses into DLLs near the top of the stack
#[cfg(feature = "trace-imports")]
fn report(signal: i32, rip: usize, context: *mut c_void) {
    let rsp = unsafe {
        (*(context as *mut libc::ucontext_t)).uc_mcontext.gregs[libc::REG_RSP as usize] as usize
    };
    eprintln!(
        "[d3dcompiler] signal {signal} at {} rsp=0x{rsp:x}",
        describe(rip)
    );
    for i in 0..2048 {
        let value = unsafe { *((rsp + i * 8) as *const usize) };
        if find_by_address(value).is_some() {
            eprintln!("[d3dcompiler]   [rsp+0x{:x}] {}", i * 8, describe(value));
        }
    }
}

/// Installs the fault handler, once, keeping whatever was installed before to pass other faults to
pub(crate) fn install() {
    PREVIOUS.get_or_init(|| unsafe {
        let mut previous: [libc::sigaction; 4] = std::mem::zeroed();
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        for (i, &signal) in SIGNALS.iter().enumerate() {
            libc::sigaction(signal, &action, &mut previous[i]);
        }
        previous
    });
}

/// The stand-in an import gets when LIBD3DCOMPILER_FAULT names it: calling it faults, to test that a
/// caller recovers from a crash inside a compiler
pub(crate) fn injected_fault(dll: &str, name: &str) -> Option<usize> {
    // writes to address 8, which nothing maps
    unsafe extern "win64" fn fault() {
        unsafe { std::ptr::write_volatile(std::ptr::dangling_mut::<u64>(), 0) };
    }
    static FAULT: OnceLock<Option<String>> = OnceLock::new();
    let wanted = FAULT
        .get_or_init(|| std::env::var("LIBD3DCOMPILER_FAULT").ok())
        .as_deref()?;
    (wanted == name || wanted.eq_ignore_ascii_case(&format!("{dll}!{name}")))
        .then_some(fault as *const () as usize)
}

// Registers where a fault in the DLLs on this thread jumps back to: a sigjmp_buf the caller set with
// sigsetjmp and keeps alive while it calls into the DLLs, or null for none. A fault clears it.
#[unsafe(no_mangle)]
pub extern "C" fn pe_set_recovery_point(recovery: *mut c_void) {
    install();
    RECOVERY.with(|r| r.set(recovery));
}

// Describes the last fault this thread recovered from, as "SIGSEGV at dxcompiler.dll+0x97e547" or,
// for a fault in an import this library provides, "SIGSEGV in an import called from ...",
// into a buffer of the given size; returns the length the description needs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_last_fault(buffer: *mut std::ffi::c_char, size: usize) -> usize {
    let (signal, rip, caller) = LAST_FAULT.with(Cell::get);
    let name = match signal {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        libc::SIGFPE => "SIGFPE",
        _ => "no fault",
    };
    let text = match (signal, find_by_address(rip), caller) {
        (0, _, _) => name.to_string(),
        (_, Some(_), _) | (_, None, 0) => format!("{name} at {}", describe(rip)),
        (_, None, caller) => format!("{name} in an import called from {}", describe(caller)),
    };
    if !buffer.is_null() && size > 0 {
        let n = text.len().min(size - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), buffer as *mut u8, n);
            *buffer.add(n) = 0;
        }
    }
    text.len() + 1
}
