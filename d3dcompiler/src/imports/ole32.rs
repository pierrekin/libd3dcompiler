//! COM's task allocator, and the BSTR strings and error objects of OLE Automation

use super::*;

// Task memory comes from the same heap as the C runtime's, as on Windows
unsafe fn task_alloc(size: usize) -> *mut c_void {
    super::heap::alloc(size, false)
}

unsafe fn task_free(p: *mut c_void) {
    super::heap::free(p)
}

unsafe fn task_size(p: *mut c_void) -> usize {
    if p.is_null() {
        usize::MAX
    } else {
        super::heap::size(p)
    }
}

unsafe fn task_realloc(p: *mut c_void, size: usize) -> *mut c_void {
    if size == 0 && !p.is_null() {
        super::heap::free(p);
        return std::ptr::null_mut();
    }
    super::heap::realloc(p, size, false)
}

// The one IMalloc, a static object whose reference count does not matter
#[repr(C)]
struct IMallocVtbl {
    query_interface: unsafe extern "win64" fn(*mut c_void, *const c_void, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "win64" fn(*mut c_void) -> u32,
    release: unsafe extern "win64" fn(*mut c_void) -> u32,
    alloc: unsafe extern "win64" fn(*mut c_void, usize) -> *mut c_void,
    realloc: unsafe extern "win64" fn(*mut c_void, *mut c_void, usize) -> *mut c_void,
    free: unsafe extern "win64" fn(*mut c_void, *mut c_void),
    get_size: unsafe extern "win64" fn(*mut c_void, *mut c_void) -> usize,
    did_alloc: unsafe extern "win64" fn(*mut c_void, *mut c_void) -> i32,
    heap_minimize: unsafe extern "win64" fn(*mut c_void),
}

unsafe extern "win64" fn malloc_query_interface(
    this: *mut c_void,
    iid: *const c_void,
    out: *mut *mut c_void,
) -> i32 {
    // IUnknown {00000000-0000-0000-C000-000000000046} and IMalloc {00000002-0000-0000-C000-000000000046}
    let iid = std::slice::from_raw_parts(iid as *const u8, 16);
    let tail = [0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
    if iid[4..] == tail && (iid[0] == 0 || iid[0] == 2) && iid[1..4] == [0, 0, 0] {
        *out = this;
        0
    } else {
        *out = std::ptr::null_mut();
        0x80004002u32 as i32 // E_NOINTERFACE
    }
}
unsafe extern "win64" fn malloc_add_ref(_this: *mut c_void) -> u32 {
    1
}
unsafe extern "win64" fn malloc_release(_this: *mut c_void) -> u32 {
    1
}
unsafe extern "win64" fn malloc_alloc(_this: *mut c_void, size: usize) -> *mut c_void {
    task_alloc(size)
}
unsafe extern "win64" fn malloc_realloc(
    _this: *mut c_void,
    p: *mut c_void,
    size: usize,
) -> *mut c_void {
    task_realloc(p, size)
}
unsafe extern "win64" fn malloc_free(_this: *mut c_void, p: *mut c_void) {
    task_free(p)
}
unsafe extern "win64" fn malloc_get_size(_this: *mut c_void, p: *mut c_void) -> usize {
    trace_call!("ole32!IMalloc::GetSize");
    task_size(p)
}
unsafe extern "win64" fn malloc_did_alloc(_this: *mut c_void, p: *mut c_void) -> i32 {
    (!p.is_null()) as i32
}
unsafe extern "win64" fn malloc_heap_minimize(_this: *mut c_void) {}

static MALLOC_VTBL: IMallocVtbl = IMallocVtbl {
    query_interface: malloc_query_interface,
    add_ref: malloc_add_ref,
    release: malloc_release,
    alloc: malloc_alloc,
    realloc: malloc_realloc,
    free: malloc_free,
    get_size: malloc_get_size,
    did_alloc: malloc_did_alloc,
    heap_minimize: malloc_heap_minimize,
};

struct Malloc(&'static IMallocVtbl);
static MALLOC: Malloc = Malloc(&MALLOC_VTBL);

// A BSTR is UTF-16 with its length in bytes in the four bytes before it, and a terminator after
unsafe fn alloc_bstr(bytes: usize) -> *mut u16 {
    let p = task_alloc(4 + bytes + 2) as *mut u8;
    if p.is_null() {
        return std::ptr::null_mut();
    }
    *(p as *mut u32) = bytes as u32;
    *(p.add(4 + bytes) as *mut u16) = 0;
    p.add(4) as *mut u16
}

import_fn! {
    fn CoGetMalloc(_dwMemContext: u32, ppMalloc: *mut *const c_void) -> i32 {
        trace_call!("ole32!CoGetMalloc");
        *ppMalloc = &MALLOC as *const Malloc as *const c_void;
        0
    }

    fn CoTaskMemAlloc(cb: usize) -> *mut c_void {
        trace_call!("ole32!CoTaskMemAlloc", "size={}", cb);
        task_alloc(cb)
    }

    fn CoTaskMemRealloc(pv: *mut c_void, cb: usize) -> *mut c_void {
        trace_call!("ole32!CoTaskMemRealloc", "size={}", cb);
        task_realloc(pv, cb)
    }

    fn CoTaskMemFree(pv: *mut c_void) {
        trace_call!("ole32!CoTaskMemFree");
        task_free(pv)
    }

    fn SysAllocString(psz: *const u16) -> *mut u16 {
        trace_call!("oleaut32!SysAllocString");
        if psz.is_null() {
            return std::ptr::null_mut();
        }
        let mut len = 0;
        while *psz.add(len) != 0 {
            len += 1;
        }
        let b = alloc_bstr(len * 2);
        if !b.is_null() {
            std::ptr::copy_nonoverlapping(psz, b, len);
        }
        b
    }

    fn SysAllocStringLen(strIn: *const u16, ui: u32) -> *mut u16 {
        trace_call!("oleaut32!SysAllocStringLen");
        let b = alloc_bstr(ui as usize * 2);
        if !b.is_null() {
            if strIn.is_null() {
                std::ptr::write_bytes(b, 0, ui as usize);
            } else {
                std::ptr::copy_nonoverlapping(strIn, b, ui as usize);
            }
        }
        b
    }

    fn SysAllocStringByteLen(psz: *const u8, len: u32) -> *mut u16 {
        trace_call!("oleaut32!SysAllocStringByteLen");
        let b = alloc_bstr(len as usize);
        if !b.is_null() {
            // a byte length can be odd, so the terminator is a whole wide character after it
            *(b as *mut u8).add(len as usize + 1) = 0;
            if psz.is_null() {
                std::ptr::write_bytes(b as *mut u8, 0, len as usize);
            } else {
                std::ptr::copy_nonoverlapping(psz, b as *mut u8, len as usize);
            }
        }
        b
    }

    fn SysFreeString(bstrString: *mut u16) {
        trace_call!("oleaut32!SysFreeString");
        if !bstrString.is_null() {
            task_free((bstrString as *mut u8).sub(4) as *mut c_void);
        }
    }

    fn SysStringLen(pbstr: *const u16) -> u32 {
        trace_call!("oleaut32!SysStringLen");
        if pbstr.is_null() { 0 } else { *((pbstr as *const u8).sub(4) as *const u32) / 2 }
    }

    fn SysStringByteLen(bstr: *const u16) -> u32 {
        trace_call!("oleaut32!SysStringByteLen");
        if bstr.is_null() { 0 } else { *((bstr as *const u8).sub(4) as *const u32) }
    }

    // No error objects are kept: setting one succeeds, and there is never one to get
    fn SetErrorInfo(_dwReserved: u32, _perrinfo: *mut c_void) -> i32 {
        trace_call!("oleaut32!SetErrorInfo");
        0
    }

    fn GetErrorInfo(_dwReserved: u32, pperrinfo: *mut *mut c_void) -> i32 {
        trace_call!("oleaut32!GetErrorInfo");
        *pperrinfo = std::ptr::null_mut();
        1 // S_FALSE
    }
}
