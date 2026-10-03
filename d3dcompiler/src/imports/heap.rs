//! The one heap behind every allocation function the DLLs call: malloc and the rest of the C
//! runtime's, HeapAlloc on any heap, LocalAlloc, COM's task allocator and BSTRs. On Windows these
//! are all the process heap underneath, and DLLs free a block from one with another.
//!
//! Each block keeps the size it was asked for in front of it, which HeapSize and IMalloc::GetSize
//! report.
//!
//! A freed block is held back before glibc can reuse it. DXC writes to some blocks after freeing
//! them, such as a reference count it decrements in an analysis node it has already deleted. On
//! Windows such a write lands in a free heap block and goes unnoticed; glibc keeps its bookkeeping in
//! free memory and aborts when it finds it changed. Holding blocks back gives those writes somewhere
//! harmless to land. With LIBD3DCOMPILER_HEAP_CHECK set, each block also ends in a guard, checked when the
//! block is freed or resized and, for every live block, every few thousand allocations, so an
//! overrun is reported with the block it hit. Freed blocks are filled and held back for a while
//! before they are released, and a block written to after it was freed is reported too.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const HEADER: usize = 16;
const MAGIC: usize = 0x4845_4150_424c_4f4b;
const GUARD: usize = 32;
const GUARD_BYTE: u8 = 0xFD;
const CHECK_EVERY: u64 = 4096;
const FREED_BYTE: u8 = 0xDD;
const QUARANTINE_BYTES: usize = 256 << 20;
const HOLD_BYTES: usize = 32 << 20;

// Freed blocks waiting to be released, and their total size
static HELD: Mutex<(std::collections::VecDeque<(usize, usize)>, usize)> =
    Mutex::new((std::collections::VecDeque::new(), 0));

unsafe fn hold(p: *mut c_void, size: usize) {
    let mut held = HELD.lock().unwrap();
    held.0.push_back((p as usize, size));
    held.1 += size;
    while held.1 > HOLD_BYTES {
        let (old, old_size) = held.0.pop_front().unwrap();
        held.1 -= old_size;
        libc::free(header(old as *mut c_void) as *mut c_void);
    }
}

// In check mode, freed blocks not yet released: address, size, allocation and free numbers, and
// where each was allocated and freed
type Freed = (usize, usize, u64, u64, Callers, Callers);
static QUARANTINE: Mutex<(std::collections::VecDeque<Freed>, usize)> =
    Mutex::new((std::collections::VecDeque::new(), 0));
static FREES: AtomicU64 = AtomicU64::new(0);

// Called for every block check mode frees, for a debugger to break on
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn libd3dcompiler_heap_freed(p: *mut c_void, size: usize) {
    unsafe { std::arch::asm!("", in("rdi") p, in("rsi") size) };
}

unsafe fn quarantine(p: *mut c_void, size: usize, number: u64, allocated_at: Callers) {
    std::ptr::write_bytes(p as *mut u8, FREED_BYTE, size);
    libd3dcompiler_heap_freed(p, size);
    let freed = FREES.fetch_add(1, Ordering::Relaxed) + 1;
    // LIBD3DCOMPILER_HEAP_TRAP names a free to stop at under a debugger, to watch its block
    static TRAP: OnceLock<Option<u64>> = OnceLock::new();
    if *TRAP.get_or_init(|| {
        std::env::var("LIBD3DCOMPILER_HEAP_TRAP")
            .ok()
            .and_then(|v| v.parse().ok())
    }) == Some(freed)
    {
        eprintln!("[d3dcompiler] heap: free {freed} is block {p:p} of {size} bytes");
        libc::raise(libc::SIGTRAP);
    }
    let mut q = QUARANTINE.lock().unwrap();
    q.0.push_back((p as usize, size, number, freed, allocated_at, dll_caller()));
    q.1 += size;
    while q.1 > QUARANTINE_BYTES {
        let block = q.0.pop_front().unwrap();
        q.1 -= block.1;
        check_freed(&block);
        libc::free(header(block.0 as *mut c_void) as *mut c_void);
    }
}

unsafe fn check_freed(&(p, size, number, freed, allocated_at, freed_at): &Freed) {
    let bytes = std::slice::from_raw_parts(p as *const u8, size);
    if let Some(at) = bytes.iter().position(|&b| b != FREED_BYTE) {
        fail(format!(
            "block 0x{p:x} of {size} bytes, allocation {number} at {}, free {freed} at {}, was written at offset {at} after it was freed",
            describe(&allocated_at),
            describe(&freed_at),
        ));
    }
}

/// Checks every freed block still held back, for writes after they were freed
pub unsafe fn check_quarantine() {
    let q = QUARANTINE.lock().unwrap();
    for block in &q.0 {
        check_freed(block);
    }
}

fn checking() -> bool {
    static CHECK: OnceLock<bool> = OnceLock::new();
    *CHECK.get_or_init(|| std::env::var_os("LIBD3DCOMPILER_HEAP_CHECK").is_some())
}

// In check mode, every live block by address, with its allocation number and the DLL code that
// allocated it
static LIVE: Mutex<Option<HashMap<usize, (u64, Callers)>>> = Mutex::new(None);

/// The first few return addresses into a DLL on the stack, nearest first: the DLL code that
/// called the shim and its callers, give or take stale values a stack scan can pick up
type Callers = [usize; 6];

fn dll_caller() -> Callers {
    super::ntdll::dll_backtrace()
}

fn describe(callers: &Callers) -> String {
    callers
        .iter()
        .filter(|&&a| a != 0)
        .map(|&a| crate::module::describe(a))
        .collect::<Vec<_>>()
        .join(" < ")
}
static COUNT: AtomicU64 = AtomicU64::new(0);

fn fail(message: String) -> ! {
    eprintln!("[d3dcompiler] heap: {message}");
    std::process::abort()
}

unsafe fn header(p: *mut c_void) -> *mut usize {
    (p as *mut u8).sub(HEADER) as *mut usize
}

unsafe fn guard_intact(p: *mut c_void) -> bool {
    let size = *header(p);
    std::slice::from_raw_parts((p as *const u8).add(size), GUARD)
        .iter()
        .all(|&b| b == GUARD_BYTE)
}

unsafe fn check_block(p: *mut c_void, (number, allocated_at): (u64, Callers), when: &str) {
    if !guard_intact(p) {
        fail(format!(
            "block {p:p} of {} bytes, allocation {number} at {}, was overrun, found {when} at allocation {}",
            *header(p),
            describe(&allocated_at),
            COUNT.load(Ordering::Relaxed)
        ));
    }
}

unsafe fn check_all() {
    if let Some(live) = LIVE.lock().unwrap().as_ref() {
        for (&p, &block) in live {
            check_block(p as *mut c_void, block, "in a sweep");
        }
    }
    check_quarantine();
}

/// Checks that p is a block of this heap, and returns its size
unsafe fn validate(p: *mut c_void) -> usize {
    let h = header(p);
    if *h.add(1) != MAGIC ^ *h {
        fail(format!(
            "{p:p} was freed or resized but is not a block of this heap"
        ));
    }
    *h
}

unsafe fn finish(base: *mut c_void, size: usize, number: u64) -> *mut c_void {
    if base.is_null() {
        return base;
    }
    let h = base as *mut usize;
    *h = size;
    *h.add(1) = MAGIC ^ size;
    let p = (base as *mut u8).add(HEADER) as *mut c_void;
    if checking() {
        std::ptr::write_bytes((p as *mut u8).add(size), GUARD_BYTE, GUARD);
        LIVE.lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(p as usize, (number, dll_caller()));
    }
    p
}

fn extra() -> usize {
    HEADER + if checking() { GUARD } else { 0 }
}

pub unsafe fn alloc(size: usize, zero: bool) -> *mut c_void {
    let number = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if checking() && number.is_multiple_of(CHECK_EVERY) {
        check_all();
    }
    let base = if zero {
        libc::calloc(1, size + extra())
    } else {
        libc::malloc(size + extra())
    };
    finish(base, size, number)
}

pub unsafe fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let size = validate(p);
    if checking() {
        let block = LIVE
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|l| l.remove(&(p as usize)))
            .unwrap_or((0, [0; 6]));
        check_block(p, block, "when it was freed");
        quarantine(p, size, block.0, block.1);
        return;
    }
    *header(p).add(1) = 0;
    hold(p, size)
}

/// Resizes a block, keeping its contents; with zero, the bytes it gains are zeroed
pub unsafe fn realloc(p: *mut c_void, size: usize, zero: bool) -> *mut c_void {
    if p.is_null() {
        return alloc(size, zero);
    }
    let old = validate(p);
    let number = if checking() {
        let block = LIVE
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|l| l.remove(&(p as usize)))
            .unwrap_or((0, [0; 6]));
        check_block(p, block, "when it was resized");
        block.0
    } else {
        0
    };
    let base = libc::realloc(header(p) as *mut c_void, size + extra());
    if base.is_null() {
        if checking() {
            LIVE.lock()
                .unwrap()
                .get_or_insert_with(HashMap::new)
                .insert(p as usize, (number, dll_caller()));
        }
        return base;
    }
    let q = finish(base, size, number);
    if zero && size > old {
        std::ptr::write_bytes((q as *mut u8).add(old), 0, size - old);
    }
    q
}

/// The size a block was asked for
pub unsafe fn size(p: *mut c_void) -> usize {
    validate(p)
}
