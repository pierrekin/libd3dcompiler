use super::*;
use std::cell::Cell;

// The C runtime's character classes for the "C" locale, as Microsoft's runtime returns them:
// _UPPER 0x1, _LOWER 0x2, _DIGIT 0x4, _SPACE 0x8, _PUNCT 0x10, _CONTROL 0x20, _BLANK 0x40, _HEX 0x80,
// _ALPHA 0x100. The is* functions return the class bits they test, not just non-zero, and callers
// can keep only the low byte, so glibc's values, which use other bits, read as false there.
fn ctype(c: i32) -> i32 {
    match c {
        0x41..=0x46 => 0x181,
        0x47..=0x5A => 0x101,
        0x61..=0x66 => 0x182,
        0x67..=0x7A => 0x102,
        0x30..=0x39 => 0x84,
        0x20 => 0x48,
        0x09 => 0x68,
        0x0A..=0x0D => 0x28,
        0x00..=0x08 | 0x0E..=0x1F | 0x7F => 0x20,
        0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => 0x10,
        _ => 0,
    }
}

// ============ msvcrt - memory ============

static ERRNO_VAL: AtomicU32 = AtomicU32::new(0);

type Win64Comparator = unsafe extern "win64" fn(*const c_void, *const c_void) -> i32;

unsafe fn swap_elements(a: *mut u8, b: *mut u8, width: usize) {
    if a != b {
        std::ptr::swap_nonoverlapping(a, b, width);
    }
}

// The Microsoft C runtime's qsort: a quicksort on the median of three, with a selection sort below
// nine elements. It is not stable, and the order it leaves equal elements in is its own, which the
// output of a compiler that sorts with it can depend on.
unsafe fn ms_qsort(base: *mut u8, num: usize, width: usize, comp: Win64Comparator) {
    const CUTOFF: usize = 8;
    if num < 2 || width == 0 {
        return;
    }
    let cmp = |a: *mut u8, b: *mut u8| comp(a as *const c_void, b as *const c_void);
    let mut stack: Vec<(*mut u8, *mut u8)> = Vec::new();
    let (mut lo, mut hi) = (base, base.add(width * (num - 1)));
    loop {
        let size = (hi as usize - lo as usize) / width + 1;
        if size <= CUTOFF {
            // repeatedly move the largest remaining element to the end
            let mut end = hi;
            while end > lo {
                let mut max = lo;
                let mut p = lo.add(width);
                while p <= end {
                    if cmp(p, max) > 0 {
                        max = p;
                    }
                    p = p.add(width);
                }
                swap_elements(max, end, width);
                end = end.sub(width);
            }
        } else {
            let mut mid = lo.add((size / 2) * width);
            if cmp(lo, mid) > 0 {
                swap_elements(lo, mid, width);
            }
            if cmp(lo, hi) > 0 {
                swap_elements(lo, hi, width);
            }
            if cmp(mid, hi) > 0 {
                swap_elements(mid, hi, width);
            }
            let (mut loguy, mut higuy) = (lo, hi);
            loop {
                if mid > loguy {
                    loop {
                        loguy = loguy.add(width);
                        if !(loguy < mid && cmp(loguy, mid) <= 0) {
                            break;
                        }
                    }
                }
                if mid <= loguy {
                    loop {
                        loguy = loguy.add(width);
                        if !(loguy <= hi && cmp(loguy, mid) <= 0) {
                            break;
                        }
                    }
                }
                loop {
                    higuy = higuy.sub(width);
                    if !(higuy > mid && cmp(higuy, mid) > 0) {
                        break;
                    }
                }
                if higuy < loguy {
                    break;
                }
                swap_elements(loguy, higuy, width);
                if mid == higuy {
                    mid = loguy;
                }
            }
            higuy = higuy.add(width);
            if mid < higuy {
                loop {
                    higuy = higuy.sub(width);
                    if !(higuy > mid && cmp(higuy, mid) == 0) {
                        break;
                    }
                }
            }
            if mid >= higuy {
                loop {
                    higuy = higuy.sub(width);
                    if !(higuy > lo && cmp(higuy, mid) == 0) {
                        break;
                    }
                }
            }
            // sort the smaller part next and keep the larger for later
            if higuy as usize - lo as usize >= hi as usize - loguy as usize {
                if lo < higuy {
                    stack.push((lo, higuy));
                }
                if loguy < hi {
                    lo = loguy;
                    continue;
                }
            } else {
                if loguy < hi {
                    stack.push((loguy, hi));
                }
                if lo < higuy {
                    hi = higuy;
                    continue;
                }
            }
        }
        match stack.pop() {
            Some((l, h)) => (lo, hi) = (l, h),
            None => return,
        }
    }
}

// The Microsoft C runtime's bsearch, which finds the same one of several equal elements it does
unsafe fn ms_bsearch(
    key: *const c_void,
    base: *const u8,
    mut num: usize,
    width: usize,
    comp: Win64Comparator,
) -> *mut c_void {
    if num == 0 {
        return std::ptr::null_mut();
    }
    let mut lo = base;
    let mut hi = base.add((num - 1) * width);
    while lo <= hi {
        let half = num / 2;
        if half != 0 {
            let mid = lo.add(if num & 1 != 0 { half } else { half - 1 } * width);
            let result = comp(key, mid as *const c_void);
            if result == 0 {
                return mid as *mut c_void;
            } else if result < 0 {
                if mid == base {
                    break;
                }
                hi = mid.sub(width);
                num = if num & 1 != 0 { half } else { half - 1 };
            } else {
                lo = mid.add(width);
                num = half;
            }
        } else if num != 0 {
            return if comp(key, lo as *const c_void) != 0 {
                std::ptr::null_mut()
            } else {
                lo as *mut c_void
            };
        } else {
            break;
        }
    }
    std::ptr::null_mut()
}

import_fn! {
    fn malloc(size: usize) -> *mut c_void {
        trace_call!("msvcrt!malloc", "size={}", size);
        super::heap::alloc(size, false)
    }

    fn free(ptr: *mut c_void) {
        trace_call!("msvcrt!free", "ptr={:p}", ptr);
        super::heap::free(ptr)
    }

    fn op_new(size: usize) -> *mut c_void {
        trace_call!("msvcrt!operator new", "size={}", size);
        libc::malloc(size.max(1))
    }

    fn op_delete(ptr: *mut c_void) {
        trace_call!("msvcrt!operator delete", "ptr={:p}", ptr);
        libc::free(ptr)
    }

    fn op_new_array(size: usize) -> *mut c_void {
        trace_call!("msvcrt!operator new[]", "size={}", size);
        libc::malloc(size.max(1))
    }

    fn op_delete_array(ptr: *mut c_void) {
        trace_call!("msvcrt!operator delete[]", "ptr={:p}", ptr);
        libc::free(ptr)
    }

    fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        trace_call!("msvcrt!memcpy", "dst={:p}, src={:p}, n={}", dst, src, n);
        libc::memcpy(dst, src, n)
    }

    fn memcpy_s(dst: *mut c_void, dst_size: usize, src: *const c_void, count: usize) -> i32 {
        trace_call!("msvcrt!memcpy_s", "dst={:p}, dst_size={}, src={:p}, count={}", dst, dst_size, src, count);
        if dst.is_null() || src.is_null() || dst_size < count {
            return 22; // EINVAL
        }
        libc::memcpy(dst, src, count);
        0
    }

    fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        trace_call!("msvcrt!memmove", "dst={:p}, src={:p}, n={}", dst, src, n);
        libc::memmove(dst, src, n)
    }

    fn memset(ptr: *mut c_void, value: i32, num: usize) -> *mut c_void {
        trace_call!("msvcrt!memset", "ptr={:p}, value={}, num={}", ptr, value, num);
        libc::memset(ptr, value, num)
    }

    fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        let r = libc::memcmp(s1, s2, n);
        trace_call!("msvcrt!memcmp", "n={} -> {}", n, r);
        r
    }

    fn _memicmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        trace_call!("msvcrt!_memicmp", "s1={:p}, s2={:p}, n={}", s1, s2, n);
        let s1 = std::slice::from_raw_parts(s1 as *const u8, n);
        let s2 = std::slice::from_raw_parts(s2 as *const u8, n);
        for i in 0..n {
            let c1 = s1[i].to_ascii_lowercase();
            let c2 = s2[i].to_ascii_lowercase();
            if c1 != c2 {
                return c1 as i32 - c2 as i32;
            }
        }
        0
    }

    // ============ msvcrt - string ============

    fn strcmp(s1: *const i8, s2: *const i8) -> i32 {
        let r = libc::strcmp(s1, s2);
        trace_call!("msvcrt!strcmp", "-> {}", r);
        r
    }

    fn strncmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
        let r = libc::strncmp(s1, s2, n);
        trace_call!("msvcrt!strncmp", "-> {}", r);
        r
    }

    fn strcpy_s(dst: *mut i8, dst_size: usize, src: *const i8) -> i32 {
        trace_call!("msvcrt!strcpy_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let len = libc::strlen(src);
        if len >= dst_size {
            return 34; // ERANGE
        }
        libc::strcpy(dst, src);
        0
    }

    fn strncpy_s(
        dst: *mut i8,
        dst_size: usize,
        src: *const i8,
        count: usize,
    ) -> i32 {
        trace_call!("msvcrt!strncpy_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let len = libc::strlen(src).min(count);
        if len >= dst_size {
            return 34;
        }
        libc::strncpy(dst, src, len);
        *dst.add(len) = 0;
        0
    }

    fn strcat_s(dst: *mut i8, dst_size: usize, src: *const i8) -> i32 {
        trace_call!("msvcrt!strcat_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let dst_len = libc::strlen(dst);
        let src_len = libc::strlen(src);
        if dst_len + src_len >= dst_size {
            return 34;
        }
        libc::strcat(dst, src);
        0
    }

    fn strchr(s: *const i8, c: i32) -> *mut i8 {
        let r = libc::strchr(s, c);
        trace_call!("msvcrt!strchr", "-> {}", if r.is_null() { "null" } else { "found" });
        r
    }

    fn strrchr(s: *const i8, c: i32) -> *mut i8 {
        let r = libc::strrchr(s, c);
        trace_call!("msvcrt!strrchr", "-> {}", if r.is_null() { "null" } else { "found" });
        r
    }

    fn strstr(haystack: *const i8, needle: *const i8) -> *mut i8 {
        let r = libc::strstr(haystack, needle);
        trace_call!("msvcrt!strstr", "-> {}", if r.is_null() { "null" } else { "found" });
        r
    }

    fn strlen(s: *const i8) -> usize {
        trace_call!("msvcrt!strlen");
        libc::strlen(s)
    }

    fn strnlen(s: *const i8, max_len: usize) -> usize {
        trace_call!("msvcrt!strnlen");
        libc::strnlen(s, max_len)
    }

    fn _strdup(s: *const i8) -> *mut i8 {
        trace_call!("msvcrt!_strdup");
        let len = libc::strlen(s) + 1;
        let dst = super::heap::alloc(len, false) as *mut i8;
        if !dst.is_null() {
            std::ptr::copy_nonoverlapping(s, dst, len);
        }
        dst
    }

    fn _stricmp(s1: *const i8, s2: *const i8) -> i32 {
        let r = libc::strcasecmp(s1, s2);
        trace_call!("msvcrt!_stricmp", "{:?} {:?} -> {}", std::ffi::CStr::from_ptr(s1), std::ffi::CStr::from_ptr(s2), r);
        r
    }

    fn _strnicmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
        let r = libc::strncasecmp(s1, s2, n);
        trace_call!("msvcrt!_strnicmp", "-> {}", r);
        r
    }

    fn tolower(c: i32) -> i32 {
        trace_call!("msvcrt!tolower");
        libc::tolower(c)
    }

    fn toupper(c: i32) -> i32 {
        let r = libc::toupper(c);
        trace_call!("msvcrt!toupper", "c=0x{:x} -> 0x{:x}", c, r);
        r
    }

    fn towlower(c: u32) -> u32 {
        trace_call!("msvcrt!towlower");
        // Simple ASCII-only lowercase
        if c >= 'A' as u32 && c <= 'Z' as u32 {
            c + 32
        } else {
            c
        }
    }

    fn isalnum(c: i32) -> i32 {
        trace_call!("msvcrt!isalnum");
        ctype(c) & 0x107
    }

    fn isalpha(c: i32) -> i32 {
        let r = ctype(c) & 0x103;
        trace_call!("msvcrt!isalpha", "c=0x{:x} -> 0x{:x}", c, r);
        r
    }

    fn isdigit(c: i32) -> i32 {
        let r = ctype(c) & 0x4;
        trace_call!("msvcrt!isdigit", "c=0x{:x} -> 0x{:x}", c, r);
        r
    }

    fn isspace(c: i32) -> i32 {
        trace_call!("msvcrt!isspace");
        ctype(c) & 0x8
    }

    fn isxdigit(c: i32) -> i32 {
        trace_call!("msvcrt!isxdigit");
        ctype(c) & 0x80
    }

    fn __isascii(c: i32) -> i32 {
        trace_call!("msvcrt!__isascii");
        if (0..=127).contains(&c) {
            1
        } else {
            0
        }
    }

    // ============ msvcrt - wide string ============

    fn wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
        trace_call!("msvcrt!wcsncmp");
        for i in 0..n {
            let c1 = *s1.add(i);
            let c2 = *s2.add(i);
            if c1 != c2 {
                return c1 as i32 - c2 as i32;
            }
            if c1 == 0 {
                return 0;
            }
        }
        0
    }

    fn wcsncpy_s(
        dst: *mut u16,
        dst_size: usize,
        src: *const u16,
        count: usize,
    ) -> i32 {
        trace_call!("msvcrt!wcsncpy_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let mut len = 0;
        while len < count && *src.add(len) != 0 {
            len += 1;
        }
        if len >= dst_size {
            return 34;
        }
        for i in 0..len {
            *dst.add(i) = *src.add(i);
        }
        *dst.add(len) = 0;
        0
    }

    fn wcsncat_s(
        dst: *mut u16,
        dst_size: usize,
        src: *const u16,
        count: usize,
    ) -> i32 {
        trace_call!("msvcrt!wcsncat_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let mut dst_len = 0;
        while *dst.add(dst_len) != 0 {
            dst_len += 1;
        }
        let mut src_len = 0;
        while src_len < count && *src.add(src_len) != 0 {
            src_len += 1;
        }
        if dst_len + src_len >= dst_size {
            return 34;
        }
        for i in 0..src_len {
            *dst.add(dst_len + i) = *src.add(i);
        }
        *dst.add(dst_len + src_len) = 0;
        0
    }

    fn wcscat_s(dst: *mut u16, dst_size: usize, src: *const u16) -> i32 {
        trace_call!("msvcrt!wcscat_s");
        wcsncat_s(dst, dst_size, src, usize::MAX)
    }

    fn wcscpy_s(dst: *mut u16, dst_size: usize, src: *const u16) -> i32 {
        trace_call!("msvcrt!wcscpy_s");
        if dst.is_null() || src.is_null() {
            return 22;
        }
        let mut len = 0;
        while *src.add(len) != 0 {
            len += 1;
        }
        if len >= dst_size {
            return 34;
        }
        for i in 0..=len {
            *dst.add(i) = *src.add(i);
        }
        0
    }

    fn wcsrchr(s: *const u16, c: u16) -> *mut u16 {
        trace_call!("msvcrt!wcsrchr");
        let mut last = std::ptr::null_mut();
        let mut p = s;
        while *p != 0 {
            if *p == c {
                last = p as *mut u16;
            }
            p = p.add(1);
        }
        last
    }

    fn wcschr(s: *const u16, c: u16) -> *mut u16 {
        trace_call!("msvcrt!wcschr");
        let mut p = s;
        loop {
            if *p == c {
                return p as *mut u16;
            }
            if *p == 0 {
                return std::ptr::null_mut();
            }
            p = p.add(1);
        }
    }

    fn _wcsdup(s: *const u16) -> *mut u16 {
        trace_call!("msvcrt!_wcsdup");
        let mut len = 0;
        while *s.add(len) != 0 {
            len += 1;
        }
        let size = (len + 1) * 2;
        let dst = super::heap::alloc(size, false) as *mut u16;
        if !dst.is_null() {
            for i in 0..=len {
                *dst.add(i) = *s.add(i);
            }
        }
        dst
    }

    fn _wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
        trace_call!("msvcrt!_wcsicmp");
        let mut i = 0;
        loop {
            let c1 = ascii_lower(*s1.add(i) as u32);
            let c2 = ascii_lower(*s2.add(i) as u32);
            if c1 != c2 {
                return c1 as i32 - c2 as i32;
            }
            if c1 == 0 {
                return 0;
            }
            i += 1;
        }
    }

    fn _wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
        trace_call!("msvcrt!_wcsnicmp");
        for i in 0..n {
            let c1 = ascii_lower(*s1.add(i) as u32);
            let c2 = ascii_lower(*s2.add(i) as u32);
            if c1 != c2 {
                return c1 as i32 - c2 as i32;
            }
            if c1 == 0 {
                return 0;
            }
        }
        0
    }

    fn _mbscmp(s1: *const u8, s2: *const u8) -> i32 {
        trace_call!("msvcrt!_mbscmp");
        libc::strcmp(s1 as *const i8, s2 as *const i8)
    }

    fn _mbstrlen(s: *const u8) -> usize {
        trace_call!("msvcrt!_mbstrlen");
        libc::strlen(s as *const i8)
    }

    // ============ msvcrt - printf/scanf ============

    fn sscanf_s(
        _buffer: *const i8,
        _format: *const i8,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
    ) -> i32 {
        trace_call!("msvcrt!sscanf_s");
        panic!("msvcrt!sscanf_s not implemented");
    }

    fn swprintf_s(
        _buffer: *mut u16,
        _size: usize,
        _format: *const u16,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
    ) -> i32 {
        trace_call!("msvcrt!swprintf_s");
        panic!("msvcrt!swprintf_s not implemented");
    }

    fn _vsnprintf(
        buffer: *mut i8,
        count: usize,
        format: *const i8,
        argptr: *mut c_void,
    ) -> i32 {
        trace_call!("msvcrt!_vsnprintf");
        super::printf::vsnprintf_core(buffer, count, format, argptr as *const u64)
    }

    fn vsprintf_s(
        buffer: *mut i8,
        size: usize,
        format: *const i8,
        argptr: *mut c_void,
    ) -> i32 {
        trace_call!("msvcrt!vsprintf_s");
        super::printf::vsnprintf_core(buffer, size, format, argptr as *const u64)
    }

    fn _vsnwprintf(
        _buffer: *mut u16,
        _count: usize,
        _format: *const u16,
        _argptr: *mut c_void,
    ) -> i32 {
        trace_call!("msvcrt!_vsnwprintf");
        panic!("msvcrt!_vsnwprintf not implemented");
    }

    fn _snwprintf_s(
        _buffer: *mut u16,
        _size_in_words: usize,
        _count: usize,
        _format: *const u16,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
    ) -> i32 {
        trace_call!("msvcrt!_snwprintf_s");
        panic!("msvcrt!_snwprintf_s not implemented");
    }

    // ============ msvcrt - file I/O ============

    fn fclose(stream: *mut c_void) -> i32 {
        trace_call!("msvcrt!fclose", "stream={:p}", stream);
        libc::fclose(stream as *mut libc::FILE)
    }

    fn fread(
        ptr: *mut c_void,
        size: usize,
        count: usize,
        stream: *mut c_void,
    ) -> usize {
        trace_call!("msvcrt!fread", "size={}, count={}", size, count);
        libc::fread(ptr, size, count, stream as *mut libc::FILE)
    }

    fn fseek(stream: *mut c_void, offset: i64, origin: i32) -> i32 {
        trace_call!("msvcrt!fseek", "offset={}, origin={}", offset, origin);
        libc::fseek(stream as *mut libc::FILE, offset as libc::c_long, origin)
    }

    fn ftell(stream: *mut c_void) -> i64 {
        trace_call!("msvcrt!ftell");
        libc::ftell(stream as *mut libc::FILE) as i64
    }

    fn _wfsopen(
        filename: *const u16,
        mode: *const u16,
        _shflag: i32,
    ) -> *mut c_void {
        trace_call!("msvcrt!_wfsopen");
        let filename = wstr_to_string(filename);
        let mode = wstr_to_string(mode);
        libc::fopen(filename.as_ptr() as *const i8, mode.as_ptr() as *const i8) as *mut c_void
    }

    fn _fileno(stream: *mut c_void) -> i32 {
        trace_call!("msvcrt!_fileno");
        libc::fileno(stream as *mut libc::FILE)
    }

    fn _filelengthi64(fd: i32) -> i64 {
        trace_call!("msvcrt!_filelengthi64", "fd={}", fd);
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut stat) == 0 {
            stat.st_size
        } else {
            -1
        }
    }

    fn _read(fd: i32, buf: *mut c_void, count: u32) -> i32 {
        trace_call!("msvcrt!_read", "fd={}, count={}", fd, count);
        libc::read(fd, buf, count as usize) as i32
    }

    fn _write(fd: i32, buf: *const c_void, count: u32) -> i32 {
        trace_call!("msvcrt!_write", "fd={}, count={}", fd, count);
        libc::write(fd, buf, count as usize) as i32
    }

    fn _close(fd: i32) -> i32 {
        trace_call!("msvcrt!_close", "fd={}", fd);
        libc::close(fd)
    }

    fn _lseeki64(fd: i32, offset: i64, origin: i32) -> i64 {
        trace_call!(
            "msvcrt!_lseeki64",
            "fd={}, offset={}, origin={}",
            fd,
            offset,
            origin
        );
        libc::lseek(fd, offset, origin)
    }

    fn _chsize_s(fd: i32, size: i64) -> i32 {
        trace_call!("msvcrt!_chsize_s", "fd={}, size={}", fd, size);
        libc::ftruncate(fd, size)
    }

    fn _chsize(fd: i32, size: i32) -> i32 {
        trace_call!("msvcrt!_chsize", "fd={}, size={}", fd, size);
        libc::ftruncate(fd, size as i64)
    }

    // pmode is variadic but only read with _O_CREAT, so taking it as a 4th arg is fine
    fn _wsopen(filename: *const u16, oflag: i32, _shflag: i32, pmode: i32) -> i32 {
        trace_call!("msvcrt!_wsopen", "oflag={:#x}, pmode={:#x}", oflag, pmode);
        let path = wstr_to_string(filename);

        let mut flags = match oflag & 3 {
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => libc::O_RDONLY,
        };
        if oflag & 0x0008 != 0 {
            flags |= libc::O_APPEND;
        }
        if oflag & 0x0080 != 0 {
            flags |= libc::O_CLOEXEC; // _O_NOINHERIT
        }
        if oflag & 0x0100 != 0 {
            flags |= libc::O_CREAT;
        }
        if oflag & 0x0200 != 0 {
            flags |= libc::O_TRUNC;
        }
        if oflag & 0x0400 != 0 {
            flags |= libc::O_EXCL;
        }

        // _S_IWRITE (0x80) controls whether the file is writable
        let mode = if pmode & 0x80 != 0 { 0o666 } else { 0o444 };
        let fd = libc::open(path.as_ptr() as *const i8, flags, mode);

        // _O_TEMPORARY: delete when closed, which unlinking now gives us
        if fd >= 0 && oflag & 0x0040 != 0 {
            libc::unlink(path.as_ptr() as *const i8);
        }
        fd
    }

    fn _get_osfhandle(fd: i32) -> isize {
        trace_call!("msvcrt!_get_osfhandle", "fd={}", fd);
        fd as isize
    }

    fn _open_osfhandle(osfhandle: isize, _flags: i32) -> i32 {
        trace_call!(
            "msvcrt!_open_osfhandle",
            "osfhandle={}, flags={}",
            osfhandle,
            _flags
        );
        osfhandle as i32
    }

    // ============ msvcrt - math ============

    fn acos(x: f64) -> f64 {
        trace_call!("msvcrt!acos");
        x.acos()
    }
    fn asin(x: f64) -> f64 {
        trace_call!("msvcrt!asin");
        x.asin()
    }
    fn atan(x: f64) -> f64 {
        trace_call!("msvcrt!atan");
        x.atan()
    }
    fn atan2(y: f64, x: f64) -> f64 {
        trace_call!("msvcrt!atan2");
        y.atan2(x)
    }
    fn ceil(x: f64) -> f64 {
        trace_call!("msvcrt!ceil");
        x.ceil()
    }
    fn cos(x: f64) -> f64 {
        trace_call!("msvcrt!cos");
        x.cos()
    }
    fn cosh(x: f64) -> f64 {
        trace_call!("msvcrt!cosh");
        x.cosh()
    }
    fn exp(x: f64) -> f64 {
        trace_call!("msvcrt!exp");
        x.exp()
    }
    fn floor(x: f64) -> f64 {
        trace_call!("msvcrt!floor");
        x.floor()
    }
    fn floorf(x: f32) -> f32 {
        trace_call!("msvcrt!floorf");
        x.floor()
    }
    fn fmod(x: f64, y: f64) -> f64 {
        trace_call!("msvcrt!fmod");
        x % y
    }
    fn log(x: f64) -> f64 {
        trace_call!("msvcrt!log");
        x.ln()
    }
    fn modf(x: f64, iptr: *mut f64) -> f64 {
        trace_call!("msvcrt!modf");
        *iptr = x.trunc();
        x.fract()
    }
    fn pow(x: f64, y: f64) -> f64 {
        trace_call!("msvcrt!pow");
        x.powf(y)
    }
    fn sin(x: f64) -> f64 {
        trace_call!("msvcrt!sin");
        x.sin()
    }
    fn sinh(x: f64) -> f64 {
        trace_call!("msvcrt!sinh");
        x.sinh()
    }
    fn sqrt(x: f64) -> f64 {
        trace_call!("msvcrt!sqrt");
        x.sqrt()
    }
    fn tan(x: f64) -> f64 {
        trace_call!("msvcrt!tan");
        x.tan()
    }
    fn tanh(x: f64) -> f64 {
        trace_call!("msvcrt!tanh");
        x.tanh()
    }

    fn _isnan(x: f64) -> i32 {
        trace_call!("msvcrt!_isnan");
        if x.is_nan() {
            1
        } else {
            0
        }
    }

    fn _finite(x: f64) -> i32 {
        trace_call!("msvcrt!_finite");
        if x.is_finite() {
            1
        } else {
            0
        }
    }

    // _FPCLASS_SNAN 0x1, QNAN 0x2, NINF 0x4, NN 0x8, ND 0x10, NZ 0x20, PZ 0x40, PD 0x80, PN 0x100,
    // PINF 0x200: sign, zero and denormal all count
    fn _fpclass(x: f64) -> i32 {
        trace_call!("msvcrt!_fpclass");
        let negative = x.is_sign_negative();
        if x.is_nan() {
            // a quiet NaN has the top bit of the mantissa set
            if x.to_bits() & (1 << 51) != 0 { 0x0002 } else { 0x0001 }
        } else if x.is_infinite() {
            if negative { 0x0004 } else { 0x0200 }
        } else if x == 0.0 {
            if negative { 0x0020 } else { 0x0040 }
        } else if x.is_subnormal() {
            if negative { 0x0010 } else { 0x0080 }
        } else if negative {
            0x0008
        } else {
            0x0100
        }
    }

    // The UCRT's FP_ classes, which differ from C's: FP_INFINITE 1, FP_NAN 2, FP_NORMAL -1,
    // FP_SUBNORMAL -2, FP_ZERO 0
    fn _dclass(x: f64) -> i16 {
        trace_call!("ucrt!_dclass");
        if x.is_nan() {
            2
        } else if x.is_infinite() {
            1
        } else if x == 0.0 {
            0
        } else if x.is_subnormal() {
            -2
        } else {
            -1
        }
    }

    fn _fdclass(x: f32) -> i16 {
        trace_call!("ucrt!_fdclass");
        if x.is_nan() {
            2
        } else if x.is_infinite() {
            1
        } else if x == 0.0 {
            0
        } else if x.is_subnormal() {
            -2
        } else {
            -1
        }
    }

    fn _clearfp() -> u32 {
        trace_call!("msvcrt!_clearfp");
        0
    }

    fn _controlfp(_new: u32, _mask: u32) -> u32 {
        trace_call!("msvcrt!_controlfp");
        0
    }

    // ============ msvcrt - conversion ============

    fn atoi(s: *const i8) -> i32 {
        trace_call!("msvcrt!atoi");
        libc::atoi(s)
    }

    fn atof(s: *const i8) -> f64 {
        trace_call!("msvcrt!atof");
        libc::atof(s)
    }

    fn _atoi64(s: *const i8) -> i64 {
        let r = libc::strtoll(s, std::ptr::null_mut(), 10);
        trace_call!("msvcrt!_atoi64", "{:?} -> {}", std::ffi::CStr::from_ptr(s), r);
        r
    }

    fn strtod(s: *const i8, endptr: *mut *mut i8) -> f64 {
        trace_call!("msvcrt!strtod");
        libc::strtod(s, endptr)
    }

    fn strtoul(s: *const i8, endptr: *mut *mut i8, base: i32) -> u64 {
        trace_call!("msvcrt!strtoul");
        libc::strtoul(s, endptr, base) as u64
    }

    fn wcstoul(s: *const u16, _endptr: *mut *mut u16, base: i32) -> u64 {
        trace_call!("msvcrt!wcstoul");
        let narrow = wstr_to_string(s);
        libc::strtoul(narrow.as_ptr() as *const i8, std::ptr::null_mut(), base) as u64
    }

    fn wcstol(s: *const u16, endptr: *mut *mut u16, base: i32) -> i32 {
        trace_call!("msvcrt!wcstol");
        let narrow = wstr_to_string(s);
        let mut end: *mut i8 = std::ptr::null_mut();
        let v = libc::strtol(narrow.as_ptr() as *const i8, &mut end, base);
        if !endptr.is_null() {
            *endptr = s.add(end.offset_from(narrow.as_ptr() as *const i8) as usize) as *mut u16;
        }
        v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
    }

    fn _strtoui64(s: *const i8, endptr: *mut *mut i8, base: i32) -> u64 {
        trace_call!("msvcrt!_strtoui64");
        libc::strtoull(s, endptr, base)
    }

    // ============ msvcrt - other ============

    fn qsort(
        base: *mut c_void,
        num: usize,
        size: usize,
        compar: *const c_void,
    ) {
        trace_call!("msvcrt!qsort", "num={}, size={}", num, size);
        ms_qsort(base as *mut u8, num, size, std::mem::transmute::<*const c_void, Win64Comparator>(compar));
    }

    fn bsearch(
        key: *const c_void,
        base: *const c_void,
        num: usize,
        size: usize,
        compar: *const c_void,
    ) -> *mut c_void {
        trace_call!("msvcrt!bsearch", "num={}, size={}", num, size);
        ms_bsearch(key, base as *const u8, num, size, std::mem::transmute::<*const c_void, Win64Comparator>(compar))
    }

    fn getenv(name: *const i8) -> *mut i8 {
        trace_call!("msvcrt!getenv");
        libc::getenv(name)
    }

    fn _wgetenv(_name: *const u16) -> *mut u16 {
        trace_call!("msvcrt!_wgetenv");
        panic!("msvcrt!_wgetenv not implemented");
    }

    // Only the "C" locale exists. Microsoft numbers the categories differently from glibc, and
    // glibc's locale must not change under the DLL, so neither is consulted.
    fn setlocale(category: i32, locale: *const i8) -> *mut i8 {
        let _ = category;
        let wanted = if locale.is_null() { None } else { Some(std::ffi::CStr::from_ptr(locale).to_bytes()) };
        trace_call!("msvcrt!setlocale", "category={} locale={:?}", category, wanted.map(String::from_utf8_lossy));
        match wanted {
            None | Some(b"") | Some(b"C") => c"C".as_ptr() as *mut i8,
            Some(_) => std::ptr::null_mut(),
        }
    }

    fn _time64(timer: *mut i64) -> i64 {
        trace_call!("msvcrt!_time64");
        let t = libc::time(std::ptr::null_mut());
        if !timer.is_null() {
            *timer = t;
        }
        t
    }

    fn _errno() -> *mut i32 {
        trace_call!("msvcrt!_errno");
        libc::__errno_location()
    }

    // ============ msvcrt - CRT init ============

    fn _initterm(start: *const *const c_void, end: *const *const c_void) {
        trace_call!("msvcrt!_initterm");
        let mut p = start;
        while p < end {
            if !(*p).is_null() {
                let f: extern "win64" fn() = std::mem::transmute(*p);
                f();
            }
            p = p.add(1);
        }
    }

    fn _amsg_exit(code: i32) {
        trace_call!("msvcrt!_amsg_exit", "code={}", code);
        std::process::exit(code);
    }

    fn _purecall() {
        trace_call!("msvcrt!_purecall");
        panic!("pure virtual function call");
    }

    fn _onexit(func: *const c_void) -> *const c_void {
        trace_call!("msvcrt!_onexit");
        func
    }

    fn __dllonexit(
        func: *const c_void,
        _pbegin: *mut *const c_void,
        _pend: *mut *const c_void,
    ) -> *const c_void {
        trace_call!("msvcrt!__dllonexit");
        func
    }

    fn _lock(_locknum: i32) {
        trace_call!("msvcrt!_lock");
        // No-op: CRT lock for thread safety
    }

    fn _unlock(_locknum: i32) {
        trace_call!("msvcrt!_unlock");
        // No-op: CRT unlock for thread safety
    }

    fn _callnewh(_size: usize) -> i32 {
        trace_call!("msvcrt!_callnewh");
        panic!("msvcrt!_callnewh not implemented");
    }

    // ============ msvcrt - exceptions ============

    fn __C_specific_handler() {
        trace_call!("msvcrt!__C_specific_handler");
        panic!("msvcrt!__C_specific_handler not implemented");
    }

    fn __CxxFrameHandler3() {
        trace_call!("msvcrt!__CxxFrameHandler3");
        panic!("msvcrt!__CxxFrameHandler3 not implemented");
    }

    fn _CxxThrowException(_obj: *mut c_void, _info: *mut c_void) {
        trace_call!("msvcrt!_CxxThrowException");
        panic!("C++ exception thrown");
    }

    fn terminate() {
        trace_call!("msvcrt!terminate");
        std::process::abort();
    }

    fn type_info_dtor() {
        trace_call!("msvcrt!type_info_dtor");
        panic!("msvcrt!type_info_dtor not implemented");
    }

    fn __unDName(
        buffer: *mut i8,
        name: *const i8,
        buflen: i32,
        _malloc: *const c_void,
        _free: *const c_void,
        _flags: u16,
    ) -> *mut i8 {
        trace_call!("msvcrt!__unDName");
        if buffer.is_null() {
            _strdup(name)
        } else {
            strcpy_s(buffer, buflen as usize, name);
            buffer
        }
    }

    fn _XcptFilter(_code: u32, _info: *mut c_void) -> i32 {
        trace_call!("msvcrt!_XcptFilter");
        panic!("msvcrt!_XcptFilter not implemented");
    }

    // ============ msvcrt - path ============

    fn _wfullpath(
        absPath: *mut u16,
        relPath: *const u16,
        maxLength: usize,
    ) -> *mut u16 {
        trace_call!("msvcrt!_wfullpath");
        wcscpy_s(absPath, maxLength, relPath);
        absPath
    }

    fn _wmakepath_s(
        path: *mut u16,
        size: usize,
        _drive: *const u16,
        dir: *const u16,
        fname: *const u16,
        ext: *const u16,
    ) -> i32 {
        trace_call!("msvcrt!_wmakepath_s");
        *path = 0;
        if !dir.is_null() {
            wcscat_s(path, size, dir);
        }
        if !fname.is_null() {
            wcscat_s(path, size, fname);
        }
        if !ext.is_null() {
            wcscat_s(path, size, ext);
        }
        0
    }

    fn _wsplitpath_s(
        _path: *const u16,
        drive: *mut u16,
        drive_size: usize,
        dir: *mut u16,
        dir_size: usize,
        fname: *mut u16,
        fname_size: usize,
        ext: *mut u16,
        ext_size: usize,
    ) -> i32 {
        trace_call!("msvcrt!_wsplitpath_s");
        if !drive.is_null() && drive_size > 0 {
            *drive = 0;
        }
        if !dir.is_null() && dir_size > 0 {
            *dir = 0;
        }
        if !fname.is_null() && fname_size > 0 {
            *fname = 0;
        }
        if !ext.is_null() && ext_size > 0 {
            *ext = 0;
        }
        0
    }
}

// ============ Variadic functions with proper naked thunks ============

/// sprintf_s - variadic printf to buffer
/// Win64 ABI: RCX=buffer, RDX=size, R8=format, R9=first_vararg, stack has rest
#[unsafe(naked)]
pub unsafe extern "win64" fn sprintf_s() -> i32 {
    std::arch::naked_asm!(
        // Store R9 (first vararg) into shadow space to make args contiguous
        "mov [rsp+0x20], r9",
        // R9 becomes pointer to varargs (va_list)
        "lea r9, [rsp+0x20]",
        "jmp {impl_fn}",
        impl_fn = sym sprintf_s_impl,
    )
}

unsafe extern "win64" fn sprintf_s_impl(
    buffer: *mut i8,
    size: usize,
    format: *const i8,
    argptr: *const u64,
) -> i32 {
    trace_call!("msvcrt!sprintf_s");
    // Text that does not fit is an invalid parameter: the buffer is emptied and -1 returned
    let text = super::printf::format(format, argptr);
    if buffer.is_null() || size == 0 {
        return -1;
    }
    if text.len() >= size {
        *buffer = 0;
        return -1;
    }
    std::ptr::copy_nonoverlapping(text.as_ptr(), buffer as *mut u8, text.len());
    *buffer.add(text.len()) = 0;
    text.len() as i32
}

#[unsafe(naked)]
pub unsafe extern "win64" fn sscanf() -> i32 {
    std::arch::naked_asm!(
        "mov [rsp+0x18], r8",
        "mov [rsp+0x20], r9",
        "lea r8, [rsp+0x18]",
        "jmp {impl_fn}",
        impl_fn = sym sscanf_impl,
    )
}

unsafe extern "win64" fn sscanf_impl(
    buffer: *const i8,
    format: *const i8,
    argptr: *const u64,
) -> i32 {
    trace_call!("msvcrt!sscanf");
    // scanf args are all pointers, so forward a fixed number and let the format pick how many get used
    // MS size prefixes (%I64, 32-bit %l) are not translated.
    let a = |i| unsafe { *argptr.add(i) as *mut c_void };
    unsafe {
        libc::sscanf(
            buffer,
            format,
            a(0),
            a(1),
            a(2),
            a(3),
            a(4),
            a(5),
            a(6),
            a(7),
        )
    }
}

// ============ Universal CRT ============
// The Universal CRT's entry points that Microsoft's own DLLs import with an _o_ prefix, and that
// have no msvcrt equivalent: DLL startup and shutdown, and the stdio functions every printf and
// scanf variant goes through.

import_fn! {
    fn calloc(count: usize, size: usize) -> *mut c_void {
        trace_call!("ucrt!calloc", "count={}, size={}", count, size);
        match count.checked_mul(size) {
            Some(total) => super::heap::alloc(total, true),
            None => std::ptr::null_mut(),
        }
    }

    fn _configure_narrow_argv(_mode: i32) -> i32 {
        trace_call!("ucrt!_configure_narrow_argv");
        0
    }

    fn _initialize_narrow_environment() -> i32 {
        trace_call!("ucrt!_initialize_narrow_environment");
        0
    }

    // A DLL's atexit table runs when it unloads, and this one stays loaded for the life of the process
    fn _initialize_onexit_table(_table: *mut c_void) -> i32 {
        trace_call!("ucrt!_initialize_onexit_table");
        0
    }

    fn _register_onexit_function(_table: *mut c_void, _func: *const c_void) -> i32 {
        trace_call!("ucrt!_register_onexit_function");
        0
    }

    fn _execute_onexit_table(_table: *mut c_void) -> i32 {
        trace_call!("ucrt!_execute_onexit_table");
        0
    }

    fn _crt_atexit(_func: *const c_void) -> i32 {
        trace_call!("ucrt!_crt_atexit");
        0
    }

    fn _cexit() {
        trace_call!("ucrt!_cexit");
    }

    fn __std_type_info_destroy_list(_list: *mut c_void) {
        trace_call!("ucrt!__std_type_info_destroy_list");
    }

    // EXCEPTION_CONTINUE_SEARCH
    fn _seh_filter_dll(_code: u32, _info: *mut c_void) -> i32 {
        trace_call!("ucrt!_seh_filter_dll");
        0
    }

    fn _invalid_parameter_noinfo() {
        trace_call!("ucrt!_invalid_parameter_noinfo");
        panic!("ucrt!_invalid_parameter_noinfo: the DLL passed an invalid parameter to the C runtime");
    }

    fn _wtoi(s: *const u16) -> i32 {
        trace_call!("ucrt!_wtoi");
        let narrow = wstr_to_string(s);
        libc::atoi(narrow.as_ptr() as *const i8)
    }

    // _O_WRONLY 1, _O_RDWR 2, _O_APPEND 8, _O_CREAT 0x100, _O_TRUNC 0x200, _O_EXCL 0x400; text and
    // binary modes do not exist here
    fn _wsopen_s(pfh: *mut i32, filename: *const u16, oflag: i32, _shflag: i32, pmode: i32) -> i32 {
        trace_call!("ucrt!_wsopen_s");
        let path = wstr_to_string(filename);
        let mut flags = match oflag & 3 {
            1 => libc::O_WRONLY,
            2 => libc::O_RDWR,
            _ => libc::O_RDONLY,
        };
        if oflag & 0x8 != 0 { flags |= libc::O_APPEND; }
        if oflag & 0x100 != 0 { flags |= libc::O_CREAT; }
        if oflag & 0x200 != 0 { flags |= libc::O_TRUNC; }
        if oflag & 0x400 != 0 { flags |= libc::O_EXCL; }
        let fd = libc::open(path.as_ptr() as *const i8, flags, if pmode != 0 { 0o644 } else { 0 });
        *pfh = fd;
        if fd < 0 { *libc::__errno_location() } else { 0 }
    }

    fn __stdio_common_vsprintf(
        options: u64,
        buffer: *mut i8,
        count: usize,
        format: *const i8,
        _locale: *mut c_void,
        arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vsprintf");
        common_vsprintf(options, buffer, count, format, arglist)
    }

    fn __stdio_common_vsprintf_s(
        options: u64,
        buffer: *mut i8,
        count: usize,
        format: *const i8,
        _locale: *mut c_void,
        arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vsprintf_s");
        common_vsprintf(options, buffer, count, format, arglist)
    }

    fn __stdio_common_vsnprintf_s(
        options: u64,
        buffer: *mut i8,
        count: usize,
        max_count: usize,
        format: *const i8,
        _locale: *mut c_void,
        arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vsnprintf_s");
        let limit = if max_count == usize::MAX { count } else { count.min(max_count + 1) };
        common_vsprintf(options, buffer, limit, format, arglist)
    }

    fn __stdio_common_vswprintf(
        _options: u64,
        _buffer: *mut u16,
        _count: usize,
        _format: *const u16,
        _locale: *mut c_void,
        _arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vswprintf");
        panic!("ucrt!__stdio_common_vswprintf not implemented");
    }

    fn __stdio_common_vswprintf_s(
        _options: u64,
        _buffer: *mut u16,
        _count: usize,
        _format: *const u16,
        _locale: *mut c_void,
        _arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vswprintf_s");
        panic!("ucrt!__stdio_common_vswprintf_s not implemented");
    }

    fn __stdio_common_vsnwprintf_s(
        _options: u64,
        _buffer: *mut u16,
        _count: usize,
        _max_count: usize,
        _format: *const u16,
        _locale: *mut c_void,
        _arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vsnwprintf_s");
        panic!("ucrt!__stdio_common_vsnwprintf_s not implemented");
    }

    fn __stdio_common_vsscanf(
        _options: u64,
        _buffer: *const i8,
        _buffer_count: usize,
        _format: *const i8,
        _locale: *mut c_void,
        _arglist: *mut c_void,
    ) -> i32 {
        trace_call!("ucrt!__stdio_common_vsscanf");
        panic!("ucrt!__stdio_common_vsscanf not implemented");
    }
}

// Formats into the buffer as the Universal CRT does. With no buffer, the caller is asking how long
// the text is. Text that fits is written with its terminator and its length returned. Text that
// fills the buffer exactly is written without a terminator, and its length returned, under
// _CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION (option 0x1), the old _vsnprintf rule.
// Longer text is cut to fit: _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR (0x2) terminates it
// and returns the full length, as C's snprintf does; otherwise it fills the buffer and returns -1.
unsafe fn common_vsprintf(
    options: u64,
    buffer: *mut i8,
    count: usize,
    format: *const i8,
    arglist: *mut c_void,
) -> i32 {
    let scratch = super::printf::format(format, arglist as *const u64);
    let len = scratch.len();
    if buffer.is_null() || count == 0 {
        return len as i32;
    }
    if len < count {
        std::ptr::copy_nonoverlapping(scratch.as_ptr() as *const i8, buffer, len);
        *buffer.add(len) = 0;
        return len as i32;
    }
    if len == count && options & 1 != 0 {
        std::ptr::copy_nonoverlapping(scratch.as_ptr() as *const i8, buffer, len);
        return len as i32;
    }
    if options & 2 != 0 {
        std::ptr::copy_nonoverlapping(scratch.as_ptr() as *const i8, buffer, count - 1);
        *buffer.add(count - 1) = 0;
        return len as i32;
    }
    std::ptr::copy_nonoverlapping(scratch.as_ptr() as *const i8, buffer, count);
    -1
}

// ============ Universal CRT - DLL entry ============

// Runs each initializer in the table and stops at the first that fails
import_fn! {
    fn _initterm_e(start: *const *const c_void, end: *const *const c_void) -> i32 {
        trace_call!("ucrt!_initterm_e");
        let mut p = start;
        while p < end {
            if !(*p).is_null() {
                let f: extern "win64" fn() -> i32 = std::mem::transmute(*p);
                let r = f();
                if r != 0 {
                    return r;
                }
            }
            p = p.add(1);
        }
        0
    }
}

// ============ Universal CRT - for Microsoft's C++ runtime and DXC ============

unsafe extern "C" {
    fn frexp(x: f64, exp: *mut i32) -> f64;
    fn ldexp(x: f64, exp: i32) -> f64;
    fn flockfile(f: *mut libc::FILE);
    fn funlockfile(f: *mut libc::FILE);
    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
}

// The "C" locale's ctype table, as __pctype_func hands it out: indexed from -1 (EOF) to 255
static PCTYPE: OnceLock<[u16; 257]> = OnceLock::new();

fn pctype() -> *const u16 {
    let table = PCTYPE.get_or_init(|| {
        let mut t = [0u16; 257];
        for c in 0..256 {
            t[c + 1] = ctype(c as i32) as u16;
        }
        t
    });
    unsafe { table.as_ptr().add(1) }
}

// Microsoft's struct lconv for the "C" locale: ten narrow strings, eight chars, eight wide strings
#[repr(C)]
struct Lconv {
    narrow: [*const i8; 10],
    chars: [i8; 8],
    wide: [*const u16; 8],
}
unsafe impl Send for Lconv {}
unsafe impl Sync for Lconv {}

static LCONV: OnceLock<Lconv> = OnceLock::new();
static WIDE_DOT: [u16; 2] = [b'.' as u16, 0];
static WIDE_EMPTY: [u16; 1] = [0];

// Six locale names, one per category, all null in the "C" locale
static LOCALE_NAMES: [usize; 6] = [0; 6];

// Microsoft's long is 32 bits: strtol and strtoul clamp to its range and report ERANGE
unsafe fn strtol32(s: *const i8, endptr: *mut *mut i8, base: i32) -> i32 {
    let v = libc::strtol(s, endptr, base);
    if v > i32::MAX as i64 {
        *libc::__errno_location() = libc::ERANGE;
        i32::MAX
    } else if v < i32::MIN as i64 {
        *libc::__errno_location() = libc::ERANGE;
        i32::MIN
    } else {
        v as i32
    }
}

thread_local! {
    // rand's state, per thread, seeded with 1 as Microsoft's is
    static RAND_SEED: Cell<u32> = const { Cell::new(1) };
}

unsafe fn wcslen16(s: *const u16) -> usize {
    let mut n = 0;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}

import_fn! {
    // math
    fn acosf(x: f32) -> f32 { trace_call!("ucrt!acosf"); x.acos() }
    fn asinf(x: f32) -> f32 { trace_call!("ucrt!asinf"); x.asin() }
    fn atanf(x: f32) -> f32 { trace_call!("ucrt!atanf"); x.atan() }
    fn atan2f(y: f32, x: f32) -> f32 { trace_call!("ucrt!atan2f"); y.atan2(x) }
    fn ceilf(x: f32) -> f32 { trace_call!("ucrt!ceilf"); x.ceil() }
    fn copysign(x: f64, y: f64) -> f64 { trace_call!("ucrt!copysign"); x.copysign(y) }
    fn cosf(x: f32) -> f32 { trace_call!("ucrt!cosf"); x.cos() }
    fn coshf(x: f32) -> f32 { trace_call!("ucrt!coshf"); x.cosh() }
    fn exp2(x: f64) -> f64 { trace_call!("ucrt!exp2"); x.exp2() }
    fn exp2f(x: f32) -> f32 { trace_call!("ucrt!exp2f"); x.exp2() }
    fn expf(x: f32) -> f32 { trace_call!("ucrt!expf"); x.exp() }
    fn fabs(x: f64) -> f64 { trace_call!("ucrt!fabs"); x.abs() }
    fn frexp_(x: f64, exp: *mut i32) -> f64 { trace_call!("ucrt!frexp"); frexp(x, exp) }
    fn ldexp_(x: f64, exp: i32) -> f64 { trace_call!("ucrt!ldexp"); ldexp(x, exp) }
    fn log10(x: f64) -> f64 { trace_call!("ucrt!log10"); x.log10() }
    fn log10f(x: f32) -> f32 { trace_call!("ucrt!log10f"); x.log10() }
    fn log2(x: f64) -> f64 { trace_call!("ucrt!log2"); x.log2() }
    fn log2f(x: f32) -> f32 { trace_call!("ucrt!log2f"); x.log2() }
    fn logf(x: f32) -> f32 { trace_call!("ucrt!logf"); x.ln() }
    fn nearbyint(x: f64) -> f64 { trace_call!("ucrt!nearbyint"); x.round_ties_even() }
    fn nearbyintf(x: f32) -> f32 { trace_call!("ucrt!nearbyintf"); x.round_ties_even() }
    fn powf(x: f32, y: f32) -> f32 { trace_call!("ucrt!powf"); x.powf(y) }
    fn round(x: f64) -> f64 { trace_call!("ucrt!round"); x.round() }
    fn roundf(x: f32) -> f32 { trace_call!("ucrt!roundf"); x.round() }
    fn sinf(x: f32) -> f32 { trace_call!("ucrt!sinf"); x.sin() }
    fn sinhf(x: f32) -> f32 { trace_call!("ucrt!sinhf"); x.sinh() }
    fn sqrtf(x: f32) -> f32 { trace_call!("ucrt!sqrtf"); x.sqrt() }
    fn tanf(x: f32) -> f32 { trace_call!("ucrt!tanf"); x.tan() }
    fn tanhf(x: f32) -> f32 { trace_call!("ucrt!tanhf"); x.tanh() }
    fn trunc(x: f64) -> f64 { trace_call!("ucrt!trunc"); x.trunc() }
    fn truncf(x: f32) -> f32 { trace_call!("ucrt!truncf"); x.trunc() }

    // the floating-point environment: only round-to-nearest, which is also the default
    fn fegetround() -> i32 { trace_call!("ucrt!fegetround"); 0 }
    fn fesetround(round: i32) -> i32 { trace_call!("ucrt!fesetround", "{}", round); (round != 0) as i32 }

    // _CW_DEFAULT: round to nearest, 53-bit precision, every exception masked
    fn _controlfp_s(current: *mut u32, _new: u32, _mask: u32) -> i32 {
        trace_call!("ucrt!_controlfp_s");
        if !current.is_null() {
            *current = 0x8001F;
        }
        0
    }

    // strings
    fn islower(c: i32) -> i32 { trace_call!("ucrt!islower"); ctype(c) & 0x2 }
    fn isupper(c: i32) -> i32 { trace_call!("ucrt!isupper"); ctype(c) & 0x1 }
    fn isprint(c: i32) -> i32 { trace_call!("ucrt!isprint"); ctype(c) & 0x157 }
    fn iswalnum(c: u16) -> i32 { trace_call!("ucrt!iswalnum"); if c < 256 { ctype(c as i32) & 0x107 } else { 0 } }
    fn iswdigit(c: u16) -> i32 { trace_call!("ucrt!iswdigit"); if c < 256 { ctype(c as i32) & 0x4 } else { 0 } }
    fn iswspace(c: u16) -> i32 { trace_call!("ucrt!iswspace"); if c < 256 { ctype(c as i32) & 0x8 } else { 0 } }
    fn iswxdigit(c: u16) -> i32 { trace_call!("ucrt!iswxdigit"); if c < 256 { ctype(c as i32) & 0x80 } else { 0 } }
    fn strcpy(dst: *mut i8, src: *const i8) -> *mut i8 { trace_call!("ucrt!strcpy"); libc::strcpy(dst, src) }
    fn strncpy(dst: *mut i8, src: *const i8, n: usize) -> *mut i8 { trace_call!("ucrt!strncpy"); libc::strncpy(dst, src, n) }
    fn strcspn(s: *const i8, reject: *const i8) -> usize { trace_call!("ucrt!strcspn"); libc::strcspn(s, reject) }
    fn strpbrk(s: *const i8, accept: *const i8) -> *mut i8 { trace_call!("ucrt!strpbrk"); libc::strpbrk(s, accept) }
    fn __strncnt(s: *const i8, n: usize) -> usize { trace_call!("ucrt!__strncnt"); libc::strnlen(s, n) }
    fn wcslen(s: *const u16) -> usize { trace_call!("ucrt!wcslen"); wcslen16(s) }
    fn wcsnlen(s: *const u16, n: usize) -> usize {
        trace_call!("ucrt!wcsnlen");
        let mut i = 0;
        while i < n && *s.add(i) != 0 {
            i += 1;
        }
        i
    }
    fn wcscmp(a: *const u16, b: *const u16) -> i32 {
        trace_call!("ucrt!wcscmp");
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y {
                return if x < y { -1 } else { 1 };
            }
            if x == 0 {
                return 0;
            }
            i += 1;
        }
    }

    // conversion
    fn atol(s: *const i8) -> i32 { trace_call!("ucrt!atol"); strtol32(s, std::ptr::null_mut(), 10) }
    fn strtol(s: *const i8, endptr: *mut *mut i8, base: i32) -> i32 { trace_call!("ucrt!strtol"); strtol32(s, endptr, base) }
    fn strtoll(s: *const i8, endptr: *mut *mut i8, base: i32) -> i64 { trace_call!("ucrt!strtoll"); libc::strtoll(s, endptr, base) }
    fn strtoull(s: *const i8, endptr: *mut *mut i8, base: i32) -> u64 { trace_call!("ucrt!strtoull"); libc::strtoull(s, endptr, base) }
    fn strtof(s: *const i8, endptr: *mut *mut i8) -> f32 { trace_call!("ucrt!strtof"); libc::strtof(s, endptr) }
    // in the "C" locale every byte is the wide character of the same value
    fn btowc(c: i32) -> u32 { trace_call!("ucrt!btowc"); if (0..256).contains(&c) { c as u32 } else { 0xFFFF } }

    // heap
    fn realloc(p: *mut c_void, size: usize) -> *mut c_void { trace_call!("ucrt!realloc"); super::heap::realloc(p, size, false) }
    fn _recalloc(p: *mut c_void, count: usize, size: usize) -> *mut c_void {
        trace_call!("ucrt!_recalloc");
        let Some(total) = count.checked_mul(size) else {
            return std::ptr::null_mut();
        };
        super::heap::realloc(p, total, true)
    }

    // utility
    fn rand() -> i32 {
        trace_call!("ucrt!rand");
        RAND_SEED.with(|seed| {
            let s = seed.get().wrapping_mul(214013).wrapping_add(2531011);
            seed.set(s);
            ((s >> 16) & 0x7FFF) as i32
        })
    }
    fn rand_s(value: *mut u32) -> i32 {
        trace_call!("ucrt!rand_s");
        libc::getrandom(value as *mut c_void, 4, 0);
        0
    }

    fn _wgetcwd(buffer: *mut u16, size: i32) -> *mut u16 {
        trace_call!("ucrt!_wgetcwd");
        let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let wide: Vec<u16> = cwd.encode_utf16().chain([0]).collect();
        let out = if buffer.is_null() {
            super::heap::alloc(wide.len().max(size as usize) * 2, false) as *mut u16
        } else if wide.len() > size as usize {
            *libc::__errno_location() = libc::ERANGE;
            return std::ptr::null_mut();
        } else {
            buffer
        };
        std::ptr::copy_nonoverlapping(wide.as_ptr(), out, wide.len());
        out
    }

    // runtime
    fn abort() { trace_call!("ucrt!abort"); std::process::abort() }
    fn exit(code: i32) { trace_call!("ucrt!exit"); std::process::exit(code) }
    fn _invalid_parameter_noinfo_noreturn() {
        trace_call!("ucrt!_invalid_parameter_noinfo_noreturn");
        eprintln!("[d3dcompiler] the DLL passed an invalid parameter to the C runtime");
        std::process::abort()
    }
    fn _invoke_watson(_expression: *const u16, _function: *const u16, _file: *const u16, _line: u32, _reserved: usize) {
        trace_call!("ucrt!_invoke_watson");
        eprintln!("[d3dcompiler] the DLL asked the C runtime to report a fatal error");
        std::process::abort()
    }
    fn _resetstkoflw() -> i32 { trace_call!("ucrt!_resetstkoflw"); 1 }
    fn _set_new_handler(_handler: *mut c_void) -> *mut c_void { trace_call!("ucrt!_set_new_handler"); std::ptr::null_mut() }
    fn _crt_at_quick_exit(_function: *mut c_void) -> i32 { trace_call!("ucrt!_crt_at_quick_exit"); 0 }

    // locale: always the "C" locale
    fn ___lc_codepage_func() -> u32 { trace_call!("ucrt!___lc_codepage_func"); 0 }
    fn ___lc_collate_cp_func() -> u32 { trace_call!("ucrt!___lc_collate_cp_func"); 0 }
    fn ___lc_locale_name_func() -> *const usize { trace_call!("ucrt!___lc_locale_name_func"); LOCALE_NAMES.as_ptr() }
    fn ___mb_cur_max_func() -> i32 { trace_call!("ucrt!___mb_cur_max_func"); 1 }
    fn __pctype_func() -> *const u16 { trace_call!("ucrt!__pctype_func"); pctype() }
    fn _lock_locales() { trace_call!("ucrt!_lock_locales"); }
    fn _unlock_locales() { trace_call!("ucrt!_unlock_locales"); }
    fn localeconv() -> *const c_void {
        trace_call!("ucrt!localeconv");
        let lconv = LCONV.get_or_init(|| {
            let empty = c"".as_ptr();
            let mut narrow = [empty; 10];
            narrow[0] = c".".as_ptr();
            let mut wide = [WIDE_EMPTY.as_ptr(); 8];
            wide[0] = WIDE_DOT.as_ptr();
            Lconv { narrow, chars: [i8::MAX; 8], wide }
        });
        lconv as *const Lconv as *const c_void
    }

    // stdio, on glibc's FILE
    fn __acrt_iob_func(index: u32) -> *mut c_void {
        trace_call!("ucrt!__acrt_iob_func", "{}", index);
        (match index {
            0 => stdin,
            1 => stdout,
            _ => stderr,
        }) as *mut c_void
    }
    fn fflush(f: *mut c_void) -> i32 { trace_call!("ucrt!fflush"); libc::fflush(f as *mut libc::FILE) }
    fn fgetc(f: *mut c_void) -> i32 { trace_call!("ucrt!fgetc"); libc::fgetc(f as *mut libc::FILE) }
    fn fputc(c: i32, f: *mut c_void) -> i32 { trace_call!("ucrt!fputc"); libc::fputc(c, f as *mut libc::FILE) }
    fn fputs(s: *const i8, f: *mut c_void) -> i32 { trace_call!("ucrt!fputs"); libc::fputs(s, f as *mut libc::FILE) }
    fn puts(s: *const i8) -> i32 { trace_call!("ucrt!puts"); libc::puts(s) }
    fn ungetc(c: i32, f: *mut c_void) -> i32 { trace_call!("ucrt!ungetc"); libc::ungetc(c, f as *mut libc::FILE) }
    fn fwrite(p: *const c_void, size: usize, count: usize, f: *mut c_void) -> usize {
        trace_call!("ucrt!fwrite");
        libc::fwrite(p, size, count, f as *mut libc::FILE)
    }
    fn setvbuf(f: *mut c_void, buf: *mut i8, mode: i32, size: usize) -> i32 {
        trace_call!("ucrt!setvbuf");
        // Microsoft's _IOFBF 0, _IOLBF 0x40, _IONBF 0x4
        let mode = match mode {
            0x4 => libc::_IONBF,
            0x40 => libc::_IOLBF,
            _ => libc::_IOFBF,
        };
        libc::setvbuf(f as *mut libc::FILE, buf, mode, size)
    }
    fn _fseeki64(f: *mut c_void, offset: i64, whence: i32) -> i32 { trace_call!("ucrt!_fseeki64"); libc::fseeko(f as *mut libc::FILE, offset, whence) }
    // Microsoft's fpos_t is the 64-bit offset
    fn fgetpos(f: *mut c_void, pos: *mut i64) -> i32 {
        trace_call!("ucrt!fgetpos");
        let p = libc::ftello(f as *mut libc::FILE);
        if p < 0 {
            return -1;
        }
        *pos = p;
        0
    }
    fn fsetpos(f: *mut c_void, pos: *const i64) -> i32 { trace_call!("ucrt!fsetpos"); libc::fseeko(f as *mut libc::FILE, *pos, libc::SEEK_SET) }
    fn _lock_file(f: *mut c_void) { trace_call!("ucrt!_lock_file"); flockfile(f as *mut libc::FILE) }
    fn _unlock_file(f: *mut c_void) { trace_call!("ucrt!_unlock_file"); funlockfile(f as *mut libc::FILE) }
    fn _fsopen(name: *const i8, mode: *const i8, _shflag: i32) -> *mut c_void {
        trace_call!("ucrt!_fsopen");
        libc::fopen(name, mode) as *mut c_void
    }
    // every stream is binary; the previous mode was too (_O_BINARY)
    fn _setmode(_fd: i32, _mode: i32) -> i32 { trace_call!("ucrt!_setmode"); 0x8000 }
    fn _lseek(fd: i32, offset: i32, whence: i32) -> i32 { trace_call!("ucrt!_lseek"); libc::lseek(fd, offset as i64, whence) as i32 }
    // Microsoft's C++ streams read and write a FILE's buffer in place, through these pointers.
    // Each stream gets an empty buffer of its own, so every read and write goes through the
    // stream's functions instead.
    fn _get_stream_buffer_pointers(f: *mut c_void, base: *mut *mut *mut i8, ptr: *mut *mut *mut i8, count: *mut *mut i32) -> i32 {
        trace_call!("ucrt!_get_stream_buffer_pointers");
        #[repr(C)]
        struct Empty { base: *mut i8, ptr: *mut i8, count: i32 }
        let _ = f;
        let empty = Box::leak(Box::new(Empty { base: std::ptr::null_mut(), ptr: std::ptr::null_mut(), count: 0 }));
        if !base.is_null() {
            *base = &mut empty.base;
        }
        if !ptr.is_null() {
            *ptr = &mut empty.ptr;
        }
        if !count.is_null() {
            *count = &mut empty.count;
        }
        0
    }

    fn __stdio_common_vfprintf(options: u64, f: *mut c_void, format: *const i8, _locale: *mut c_void, arglist: *mut c_void) -> i32 {
        trace_call!("ucrt!__stdio_common_vfprintf");
        let len = common_vsprintf(options | 2, std::ptr::null_mut(), 0, format, arglist);
        if len < 0 {
            return len;
        }
        let mut buf = vec![0i8; len as usize + 1];
        common_vsprintf(options | 2, buf.as_mut_ptr(), buf.len(), format, arglist);
        libc::fwrite(buf.as_ptr() as *const c_void, 1, len as usize, f as *mut libc::FILE) as i32
    }
}
