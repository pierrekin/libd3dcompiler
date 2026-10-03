pub mod advapi32;
pub mod heap;
pub mod kernel32;
pub mod msvcrt;
pub mod ntdll;
pub mod ole32;
pub mod printf;
pub mod rpcrt4;

use super::*;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// Caller address captured by thunks (set before calling impl)
pub static CALLER_ADDR: AtomicUsize = AtomicUsize::new(0);

// DLL address space info (set by loader, used to convert runtime addresses to original VA)
pub static DLL_MAP_BASE: AtomicUsize = AtomicUsize::new(0);
pub static DLL_MAP_SIZE: AtomicUsize = AtomicUsize::new(0);
pub static DLL_IMAGE_BASE: AtomicUsize = AtomicUsize::new(0);

/// Convert a runtime address to the DLL's original (unrelocated) VA
#[inline]
pub fn to_original_va(addr: usize) -> usize {
    let map_base = DLL_MAP_BASE.load(Ordering::Relaxed);
    let map_size = DLL_MAP_SIZE.load(Ordering::Relaxed);
    let image_base = DLL_IMAGE_BASE.load(Ordering::Relaxed);

    if map_base != 0 && addr >= map_base && addr < map_base + map_size {
        // Address is within DLL, convert to original VA
        addr - map_base + image_base
    } else {
        // Address outside DLL, return as-is
        addr
    }
}

macro_rules! trace_call {
    ($name:expr) => {
        #[cfg(feature = "trace-imports")]
        eprintln!("[IMPORT] {}", $name);
    };
    ($name:expr, $($arg:tt)*) => {
        #[cfg(feature = "trace-imports")]
        eprintln!("[IMPORT] {} - {}", $name, format!($($arg)*));
    };
}

pub(crate) use trace_call;

macro_rules! import_fn {
    // Entry point - parse multiple functions
    ($($tt:tt)*) => {
        $crate::imports::import_fn_inner!($($tt)*);
    };
}

macro_rules! import_fn_inner {
    // With return type
    (fn $name:ident($($arg:ident : $argty:ty),* $(,)?) -> $ret:ty $body:block $($rest:tt)*) => {
        ::paste::paste! {
            #[unsafe(naked)]
            pub unsafe extern "win64" fn $name( $(_: $argty),* ) -> $ret {
                std::arch::naked_asm!(
                    // "mov r11, [rsp]",
                    // "mov [rip + {caller}], r11",
                    "jmp {impl_fn}",
                    // caller = sym $crate::imports::CALLER_ADDR,
                    impl_fn = sym [<$name _impl>],
                )
            }

            unsafe extern "win64" fn [<$name _impl>]( $($arg : $argty),* ) -> $ret $body
        }

        $crate::imports::import_fn_inner!($($rest)*);
    };

    // Without return type (void)
    (fn $name:ident($($arg:ident : $argty:ty),* $(,)?) $body:block $($rest:tt)*) => {
        ::paste::paste! {
            #[unsafe(naked)]
            pub unsafe extern "win64" fn $name( $(_: $argty),* ) {
                std::arch::naked_asm!(
                    // "mov r11, [rsp]",
                    // "mov [rip + {caller}], r11",
                    "jmp {impl_fn}",
                    // caller = sym $crate::imports::CALLER_ADDR,
                    impl_fn = sym [<$name _impl>],
                )
            }

            unsafe extern "win64" fn [<$name _impl>]( $($arg : $argty),* ) $body
        }

        $crate::imports::import_fn_inner!($($rest)*);
    };

    // Base case - empty
    () => {};
}

pub(crate) use import_fn;
pub(crate) use import_fn_inner;

// ============ Helpers ============

unsafe fn wstr_to_string(s: *const u16) -> Vec<u8> {
    let mut result = Vec::new();
    let mut p = s;
    while *p != 0 {
        let c = *p;
        if c < 128 {
            result.push(c as u8);
        } else {
            result.push(b'?');
        }
        p = p.add(1);
    }
    result.push(0);
    result
}

// Helper for ASCII lowercase
fn ascii_lower(c: u32) -> u32 {
    if c >= 'A' as u32 && c <= 'Z' as u32 {
        c + 32
    } else {
        c
    }
}

fn ascii_upper(c: u32) -> u32 {
    if c >= 'a' as u32 && c <= 'z' as u32 {
        c - 32
    } else {
        c
    }
}
