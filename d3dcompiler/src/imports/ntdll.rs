//! Windows x64 exception handling: raising an exception, walking the stack with the DLLs' unwind
//! tables, calling their language handlers to find a catch and unwind to it, and resuming there.
//! It follows Wine's ntdll, which follows Windows.
//!
//! The stack also holds frames of this library's own code, which have no unwind tables. Where the
//! walk reaches one, it carries on from a context saved when that code was entered from a DLL: the
//! caller of RaiseException, or the frame a catch block returns to.

use super::*;
use std::cell::RefCell;

pub const CONTEXT_SIZE: usize = 0x4D0;

#[repr(C, align(16))]
#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct CONTEXT {
    data: [u8; CONTEXT_SIZE],
}

impl CONTEXT {
    // Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8 to R15, in the order unwind codes number them
    fn reg(&mut self, i: usize) -> &mut u64 {
        unsafe { &mut *(self.data.as_mut_ptr().add(0x78 + i * 8) as *mut u64) }
    }
    fn rsp(&mut self) -> &mut u64 {
        self.reg(4)
    }
    fn stack_pointer(&self) -> u64 {
        u64::from_le_bytes(self.data[0x98..0xA0].try_into().unwrap())
    }
    fn rip(&mut self) -> &mut u64 {
        unsafe { &mut *(self.data.as_mut_ptr().add(0xF8) as *mut u64) }
    }
    fn xmm(&mut self, i: usize) -> *mut [u8; 16] {
        unsafe { self.data.as_mut_ptr().add(0x1A0 + i * 16) as *mut [u8; 16] }
    }
}

#[repr(C)]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub UnwindData: u32,
}

#[repr(C)]
pub struct EXCEPTION_RECORD {
    code: u32,
    flags: u32,
    record: *mut EXCEPTION_RECORD,
    address: usize,
    count: u32,
    information: [usize; 15],
}

#[repr(C)]
struct DISPATCHER_CONTEXT {
    control_pc: usize,
    image_base: usize,
    function_entry: *const RUNTIME_FUNCTION,
    establisher_frame: usize,
    target_ip: usize,
    context: *mut CONTEXT,
    language_handler: usize,
    handler_data: *mut c_void,
    history_table: *mut c_void,
    scope_index: u32,
    fill: u32,
}

const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const EXCEPTION_UNWINDING: u32 = 0x2;
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
const STATUS_UNWIND: u32 = 0xC0000027;
const STATUS_UNWIND_CONSOLIDATE: u32 = 0x80000029;
const UNW_FLAG_EHANDLER: u32 = 1;
const UNW_FLAG_UHANDLER: u32 = 2;
const UNW_FLAG_CHAININFO: u32 = 4;

type LanguageHandler = unsafe extern "win64" fn(
    *mut EXCEPTION_RECORD,
    usize,
    *mut CONTEXT,
    *mut DISPATCHER_CONTEXT,
) -> u32;

thread_local! {
    // Where the walk resumes when it reaches this library's own frames, most recent last
    static BRIDGES: RefCell<Vec<CONTEXT>> = const { RefCell::new(Vec::new()) };
}

fn push_bridge(context: &CONTEXT) {
    BRIDGES.with(|b| b.borrow_mut().push(context.clone()));
}

fn pop_bridge() {
    BRIDGES.with(|b| b.borrow_mut().pop());
}

/// The most recent saved context that is further up the stack than rsp
fn bridge_above(rsp: u64) -> Option<CONTEXT> {
    BRIDGES.with(|b| {
        b.borrow()
            .iter()
            .rev()
            .find(|c| c.stack_pointer() > rsp)
            .cloned()
    })
}

fn fatal(message: &str) -> ! {
    eprintln!("[d3dcompiler] {message}");
    std::process::abort()
}

/// The unwind table entry for an address in a loaded DLL, and that DLL's base
pub(crate) unsafe fn lookup_function_entry(pc: usize) -> Option<(*const RUNTIME_FUNCTION, usize)> {
    let module = crate::module::find_by_address(pc)?;
    let (rva, size) = module.exception_table;
    if size == 0 {
        return None;
    }
    let base = module.base;
    let entries = std::slice::from_raw_parts((base + rva) as *const RUNTIME_FUNCTION, size / 12);
    let offset = (pc - base) as u32;
    let i = entries.partition_point(|e| e.EndAddress <= offset);
    let entry = entries.get(i).filter(|e| e.BeginAddress <= offset)?;
    // an entry whose unwind data is odd points at another entry, which holds the real data
    let entry = if entry.UnwindData & 1 != 0 {
        (base + (entry.UnwindData & !1) as usize) as *const RUNTIME_FUNCTION
    } else {
        entry as *const RUNTIME_FUNCTION
    };
    Some((entry, base))
}

/// Unwinds one frame in place, from its unwind codes, and returns its handler of the given type
#[allow(clippy::too_many_arguments)]
unsafe fn virtual_unwind(
    handler_type: u32,
    base: usize,
    pc: usize,
    mut function: *const RUNTIME_FUNCTION,
    context: &mut CONTEXT,
    data: &mut *mut c_void,
    frame_ret: &mut usize,
    pointers: *mut usize,
) -> usize {
    let mut frame = *context.rsp() as usize;
    *frame_ret = frame;
    let mut mach_frame = false;
    let (mut flags, mut handler_at, mut prolog_offset);
    loop {
        let info = (base + (*function).UnwindData as usize) as *const u8;
        let version = *info & 7;
        flags = (*info >> 3) as u32;
        let prolog = *info.add(1) as usize;
        let count = *info.add(2) as usize;
        let frame_reg = (*info.add(3) & 0xF) as usize;
        let frame_offset = (*info.add(3) >> 4) as usize;
        let codes = info.add(4) as *const u16;
        handler_at = codes.add((count + 1) & !1) as *const u8;
        if version != 1 && version != 2 {
            fatal(&format!("unwind info version {version} at {info:p}"));
        }
        if frame_reg != 0 {
            frame = (*context.reg(frame_reg) as usize).wrapping_sub(frame_offset * 16);
        }
        let begin = base + (*function).BeginAddress as usize;
        prolog_offset = if pc >= begin && pc < begin + prolog {
            pc - begin
        } else {
            usize::MAX
        };

        let mut i = 0;
        while i < count {
            let code = *codes.add(i);
            let (offset, op, op_info) = (
                (code & 0xFF) as usize,
                (code >> 8) & 0xF,
                (code >> 12) as usize,
            );
            let size = match op {
                1 => 2 + (op_info != 0) as usize,
                4 | 8 | 6 => 2,
                5 | 9 => 3,
                _ => 1,
            };
            let arg16 = *codes.add(i + 1) as usize;
            let arg32 = arg16 | (*codes.add(i + 2) as usize) << 16;
            if prolog_offset < offset {
                i += size;
                continue;
            }
            match op {
                0 => {
                    let at = *context.rsp() as usize;
                    save_reg(context, pointers, op_info, at);
                    *context.rsp() += 8;
                }
                1 => *context.rsp() += if op_info != 0 { arg32 } else { arg16 * 8 } as u64,
                2 => *context.rsp() += (op_info as u64 + 1) * 8,
                3 => {
                    *context.rsp() = frame as u64;
                    *frame_ret = frame;
                }
                4 => save_reg(context, pointers, op_info, frame + arg16 * 8),
                5 => save_reg(context, pointers, op_info, frame + arg32),
                6 => {}
                8 | 9 => {
                    let at = frame + if op == 8 { arg16 * 16 } else { arg32 };
                    *context.xmm(op_info) = *(at as *const [u8; 16]);
                    if !pointers.is_null() {
                        *pointers.add(op_info) = at;
                    }
                }
                10 => {
                    if op_info != 0 {
                        *context.rsp() += 8;
                    }
                    let rsp = *context.rsp() as usize;
                    *context.rip() = *(rsp as *const u64);
                    *context.rsp() = *((rsp + 24) as *const u64);
                    mach_frame = true;
                }
                _ => fatal(&format!("unwind code {op} at {info:p}")),
            }
            i += size;
        }
        if flags & UNW_FLAG_CHAININFO == 0 {
            break;
        }
        function = handler_at as *const RUNTIME_FUNCTION;
    }
    if !mach_frame {
        let rsp = *context.rsp() as usize;
        *context.rip() = *(rsp as *const u64);
        *context.rsp() += 8;
    }
    if flags & handler_type == 0 || prolog_offset != usize::MAX {
        return 0;
    }
    *data = handler_at.add(4) as *mut c_void;
    base + *(handler_at as *const u32) as usize
}

// Restores a register an unwind code says was saved at an address, and notes where it was
unsafe fn save_reg(context: &mut CONTEXT, pointers: *mut usize, reg: usize, at: usize) {
    *context.reg(reg) = *(at as *const u64);
    if !pointers.is_null() {
        *pointers.add(16 + reg) = at;
    }
}

struct Frame {
    handler: usize,
    data: *mut c_void,
    establisher: usize,
    function: *const RUNTIME_FUNCTION,
    base: usize,
}

/// Unwinds the frame of context into next. Frames of this library's code are passed over to the
/// DLL frame that called into it.
unsafe fn unwind_frame(
    handler_type: u32,
    context: &mut CONTEXT,
    next: &mut CONTEXT,
) -> Option<Frame> {
    let pc = *context.rip() as usize;
    *next = context.clone();
    if let Some((function, base)) = lookup_function_entry(pc) {
        let mut frame = Frame {
            handler: 0,
            data: std::ptr::null_mut(),
            establisher: 0,
            function,
            base,
        };
        frame.handler = virtual_unwind(
            handler_type,
            base,
            pc,
            function,
            next,
            &mut frame.data,
            &mut frame.establisher,
            std::ptr::null_mut(),
        );
        return Some(frame);
    }
    let establisher = *context.rsp() as usize;
    if crate::module::find_by_address(pc).is_some() {
        // a leaf function: nothing but the return address on the stack
        let rsp = *next.rsp() as usize;
        *next.rip() = *(rsp as *const u64);
        *next.rsp() += 8;
    } else {
        *next = bridge_above(*context.rsp())?;
    }
    Some(Frame {
        handler: 0,
        data: std::ptr::null_mut(),
        establisher,
        function: std::ptr::null(),
        base: 0,
    })
}

unsafe fn call_handler(
    frame: &Frame,
    record: *mut EXCEPTION_RECORD,
    context: &mut CONTEXT,
    target_ip: usize,
) -> u32 {
    let mut dispatch = DISPATCHER_CONTEXT {
        control_pc: *context.rip() as usize,
        image_base: frame.base,
        function_entry: frame.function,
        establisher_frame: frame.establisher,
        target_ip,
        context,
        language_handler: frame.handler,
        handler_data: frame.data,
        history_table: std::ptr::null_mut(),
        scope_index: 0,
        fill: 0,
    };
    let handler = std::mem::transmute::<usize, LanguageHandler>(frame.handler);
    handler(record, frame.establisher, context, &mut dispatch)
}

/// Looks for a frame whose handler takes the exception. A C++ catch never returns here: its
/// handler unwinds to it.
unsafe extern "win64" fn raise_exception(
    code: u32,
    flags: u32,
    count: u32,
    arguments: *const usize,
    context: *mut CONTEXT,
) -> ! {
    let context = &mut *context;
    let mut record = EXCEPTION_RECORD {
        code,
        flags: flags & EXCEPTION_NONCONTINUABLE,
        record: std::ptr::null_mut(),
        address: *context.rip() as usize,
        count: count.min(15),
        information: [0; 15],
    };
    if !arguments.is_null() {
        std::ptr::copy_nonoverlapping(
            arguments,
            record.information.as_mut_ptr(),
            record.count as usize,
        );
    }
    trace_call!(
        "kernel32!RaiseException",
        "code=0x{:x} at 0x{:x}",
        code,
        record.address
    );
    push_bridge(context);

    let mut current = context.clone();
    let mut next = context.clone();
    loop {
        let Some(frame) = unwind_frame(UNW_FLAG_EHANDLER, &mut current, &mut next) else {
            fatal(&format!(
                "exception 0x{code:x} raised at 0x{:x} was not handled",
                record.address
            ));
        };
        if frame.handler != 0 {
            match call_handler(&frame, &mut record, &mut current, 0) {
                0 => {
                    if record.flags & EXCEPTION_NONCONTINUABLE != 0 {
                        fatal("a handler continued a noncontinuable exception");
                    }
                    pop_bridge();
                    restore_context(context);
                }
                1 | 2 => {}
                r => fatal(&format!("exception handler returned {r}")),
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
}

/// Unwinds every frame from the caller up to and including target_frame, calling their unwind
/// handlers, then resumes at target_ip in that frame
unsafe extern "win64" fn rtl_unwind_ex(
    target_frame: usize,
    target_ip: usize,
    record: *mut EXCEPTION_RECORD,
    return_value: usize,
    context_record: *mut CONTEXT,
    _history: *mut c_void,
    captured: *mut CONTEXT,
) -> ! {
    let mut local_record;
    let record = if record.is_null() {
        local_record = EXCEPTION_RECORD {
            code: STATUS_UNWIND,
            flags: 0,
            record: std::ptr::null_mut(),
            address: *(*captured).rip() as usize,
            count: 0,
            information: [0; 15],
        };
        &mut local_record
    } else {
        &mut *record
    };
    trace_call!(
        "ntdll!RtlUnwindEx",
        "frame=0x{:x} ip=0x{:x} code=0x{:x}",
        target_frame,
        target_ip,
        record.code
    );
    record.flags |= EXCEPTION_UNWINDING;
    let mut local_context;
    let context = if context_record.is_null() {
        local_context = (*captured).clone();
        &mut local_context
    } else {
        *context_record = (*captured).clone();
        &mut *context_record
    };
    let mut next = context.clone();
    loop {
        let Some(frame) = unwind_frame(UNW_FLAG_UHANDLER, context, &mut next) else {
            fatal(&format!(
                "unwinding to frame 0x{target_frame:x} ran off the stack"
            ));
        };
        if target_frame != 0 && frame.establisher > target_frame {
            fatal(&format!(
                "unwinding passed frame 0x{target_frame:x} without finding it"
            ));
        }
        if frame.establisher == target_frame {
            record.flags |= EXCEPTION_TARGET_UNWIND;
        }
        if frame.handler != 0 {
            match call_handler(&frame, record, context, target_ip) {
                1 => {}
                r => fatal(&format!("unwind handler returned {r}")),
            }
        }
        if frame.establisher == target_frame {
            break;
        }
        *context = next.clone();
    }
    *context.reg(0) = return_value as u64;
    *context.rip() = target_ip as u64;
    if record.code == STATUS_UNWIND_CONSOLIDATE {
        // the callback runs the catch block and returns where to resume; an exception raised in
        // it walks out of this library to the frame being resumed
        type Consolidate = unsafe extern "win64" fn(*mut EXCEPTION_RECORD) -> usize;
        let callback = std::mem::transmute::<usize, Consolidate>(record.information[0]);
        push_bridge(context);
        let ip = callback(record);
        pop_bridge();
        *context.rip() = ip as u64;
    }
    restore_context(context);
}

/// Resumes execution with the registers of context, dropping the saved contexts it leaves behind
unsafe fn restore_context(context: &mut CONTEXT) -> ! {
    let rsp = *context.rsp();
    BRIDGES.with(|b| b.borrow_mut().retain(|c| c.stack_pointer() >= rsp));
    restore(context)
}

// Fills the CONTEXT at r11 with the registers as the caller will see them once the function
// returns, given the distance from rsp to the return address
macro_rules! capture {
    ($ret:literal) => {
        concat!(
            "mov [r11+0x78], rax\n",
            "mov [r11+0x80], rcx\n",
            "mov [r11+0x88], rdx\n",
            "mov [r11+0x90], rbx\n",
            "lea rax, [rsp+",
            $ret,
            "+8]\n",
            "mov [r11+0x98], rax\n",
            "mov [r11+0xA0], rbp\n",
            "mov [r11+0xA8], rsi\n",
            "mov [r11+0xB0], rdi\n",
            "mov [r11+0xB8], r8\n",
            "mov [r11+0xC0], r9\n",
            "mov [r11+0xC8], r10\n",
            "mov qword ptr [r11+0xD0], 0\n",
            "mov [r11+0xD8], r12\n",
            "mov [r11+0xE0], r13\n",
            "mov [r11+0xE8], r14\n",
            "mov [r11+0xF0], r15\n",
            "mov rax, [rsp+",
            $ret,
            "]\n",
            "mov [r11+0xF8], rax\n",
            "movdqu [r11+0x1A0], xmm0\n",
            "movdqu [r11+0x1B0], xmm1\n",
            "movdqu [r11+0x1C0], xmm2\n",
            "movdqu [r11+0x1D0], xmm3\n",
            "movdqu [r11+0x1E0], xmm4\n",
            "movdqu [r11+0x1F0], xmm5\n",
            "movdqu [r11+0x200], xmm6\n",
            "movdqu [r11+0x210], xmm7\n",
            "movdqu [r11+0x220], xmm8\n",
            "movdqu [r11+0x230], xmm9\n",
            "movdqu [r11+0x240], xmm10\n",
            "movdqu [r11+0x250], xmm11\n",
            "movdqu [r11+0x260], xmm12\n",
            "movdqu [r11+0x270], xmm13\n",
            "movdqu [r11+0x280], xmm14\n",
            "movdqu [r11+0x290], xmm15\n",
            "stmxcsr [r11+0x34]\n",
            "stmxcsr [r11+0x118]\n",
            "fnstcw [r11+0x100]\n",
            "pushfq\n",
            "pop rax\n",
            "mov [r11+0x44], eax\n",
            "mov dword ptr [r11+0x30], 0x10001F\n",
            "mov ax, cs\n",
            "mov [r11+0x38], ax\n",
            "mov ax, ss\n",
            "mov [r11+0x42], ax\n",
            "mov rax, [r11+0x78]\n",
        )
    };
}

// Jumps to the context's Rip with its stack and registers
#[unsafe(naked)]
unsafe extern "win64" fn restore(_context: *mut CONTEXT) -> ! {
    std::arch::naked_asm!(
        "ldmxcsr [rcx+0x34]",
        "fldcw [rcx+0x100]",
        "movdqu xmm0, [rcx+0x1A0]",
        "movdqu xmm1, [rcx+0x1B0]",
        "movdqu xmm2, [rcx+0x1C0]",
        "movdqu xmm3, [rcx+0x1D0]",
        "movdqu xmm4, [rcx+0x1E0]",
        "movdqu xmm5, [rcx+0x1F0]",
        "movdqu xmm6, [rcx+0x200]",
        "movdqu xmm7, [rcx+0x210]",
        "movdqu xmm8, [rcx+0x220]",
        "movdqu xmm9, [rcx+0x230]",
        "movdqu xmm10, [rcx+0x240]",
        "movdqu xmm11, [rcx+0x250]",
        "movdqu xmm12, [rcx+0x260]",
        "movdqu xmm13, [rcx+0x270]",
        "movdqu xmm14, [rcx+0x280]",
        "movdqu xmm15, [rcx+0x290]",
        // the return address goes just below the new stack pointer, and ret pops it
        "mov r11, [rcx+0x98]",
        "sub r11, 8",
        "mov rax, [rcx+0xF8]",
        "mov [r11], rax",
        "mov rax, [rcx+0x78]",
        "mov rdx, [rcx+0x88]",
        "mov rbx, [rcx+0x90]",
        "mov rbp, [rcx+0xA0]",
        "mov rsi, [rcx+0xA8]",
        "mov rdi, [rcx+0xB0]",
        "mov r8, [rcx+0xB8]",
        "mov r9, [rcx+0xC0]",
        "mov r10, [rcx+0xC8]",
        "mov r12, [rcx+0xD8]",
        "mov r13, [rcx+0xE0]",
        "mov r14, [rcx+0xE8]",
        "mov r15, [rcx+0xF0]",
        "mov rsp, r11",
        "mov rcx, [rcx+0x80]",
        "ret",
    )
}

#[unsafe(naked)]
pub unsafe extern "win64" fn RtlCaptureContext(_context: *mut CONTEXT) {
    std::arch::naked_asm!("mov r11, rcx", capture!("0"), "ret")
}

#[unsafe(naked)]
pub unsafe extern "win64" fn RaiseException(
    _code: u32,
    _flags: u32,
    _count: u32,
    _arguments: *const usize,
) -> ! {
    std::arch::naked_asm!(
        "sub rsp, 0x508",
        "lea r11, [rsp+0x30]",
        capture!("0x508"),
        "mov [rsp+0x20], r11",
        "call {raise}",
        "ud2",
        raise = sym raise_exception,
    )
}

#[unsafe(naked)]
pub unsafe extern "win64" fn RtlUnwindEx(
    _target_frame: usize,
    _target_ip: usize,
    _record: *mut EXCEPTION_RECORD,
    _return_value: usize,
    _context: *mut CONTEXT,
    _history: *mut c_void,
) -> ! {
    std::arch::naked_asm!(
        "sub rsp, 0x518",
        "lea r11, [rsp+0x40]",
        capture!("0x518"),
        "mov rax, [rsp+0x518+0x28]",
        "mov [rsp+0x20], rax",
        "mov rax, [rsp+0x518+0x30]",
        "mov [rsp+0x28], rax",
        "mov [rsp+0x30], r11",
        "call {unwind}",
        "ud2",
        unwind = sym rtl_unwind_ex,
    )
}

#[unsafe(naked)]
pub unsafe extern "win64" fn RtlUnwind(
    _target_frame: usize,
    _target_ip: usize,
    _record: *mut EXCEPTION_RECORD,
    _return_value: usize,
) -> ! {
    std::arch::naked_asm!(
        "sub rsp, 0x38",
        "mov qword ptr [rsp+0x20], 0",
        "mov qword ptr [rsp+0x28], 0",
        "call {unwind}",
        "ud2",
        unwind = sym RtlUnwindEx,
    )
}

import_fn! {
    fn RtlLookupFunctionEntry(pc: u64, image_base: *mut u64, _history_table: *mut c_void) -> *const RUNTIME_FUNCTION {
        trace_call!("ntdll!RtlLookupFunctionEntry", "pc=0x{:x}", pc);
        match lookup_function_entry(pc as usize) {
            Some((entry, base)) => {
                *image_base = base as u64;
                entry
            }
            None => std::ptr::null(),
        }
    }

    fn RtlVirtualUnwind(
        handler_type: u32,
        image_base: u64,
        control_pc: u64,
        function_entry: *const RUNTIME_FUNCTION,
        context: *mut CONTEXT,
        handler_data: *mut *mut c_void,
        establisher_frame: *mut u64,
        context_pointers: *mut usize,
    ) -> usize {
        trace_call!("ntdll!RtlVirtualUnwind", "pc=0x{:x}", control_pc);
        let mut data = std::ptr::null_mut();
        let mut frame = 0;
        let handler = virtual_unwind(
            handler_type,
            image_base as usize,
            control_pc as usize,
            function_entry,
            &mut *context,
            &mut data,
            &mut frame,
            context_pointers,
        );
        *handler_data = data;
        *establisher_frame = frame as u64;
        handler
    }

    fn RtlPcToFileHeader(pc: usize, base_of_image: *mut usize) -> usize {
        trace_call!("ntdll!RtlPcToFileHeader", "pc=0x{:x}", pc);
        let base = crate::module::find_by_address(pc).map_or(0, |m| m.base);
        *base_of_image = base;
        base
    }
}
