use super::*;

use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;

static EXCEPTION_FILTER: AtomicU64 = AtomicU64::new(0);
const PROCESS_HEAP: u32 = 0x12345678;
static HEAP_NEXT: AtomicU32 = AtomicU32::new(PROCESS_HEAP + 1);
static HEAP_ALLOCS: OnceLock<Mutex<HashMap<u32, Vec<usize>>>> = OnceLock::new();
fn heap_table() -> &'static Mutex<HashMap<u32, Vec<usize>>> {
    HEAP_ALLOCS.get_or_init(|| Mutex::new(HashMap::new()))
}
static VIRT_REGIONS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

fn virt_table() -> &'static Mutex<HashMap<usize, usize>> {
    VIRT_REGIONS.get_or_init(|| Mutex::new(HashMap::new()))
}
static HANDLE_MAP: OnceLock<RwLock<HashMap<usize, i32>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(0x1000);
static MMAP_MAP: OnceLock<RwLock<HashMap<usize, (usize, usize)>>> = OnceLock::new();
static TLS_SLOTS: OnceLock<RwLock<HashMap<u32, libc::pthread_key_t>>> = OnceLock::new();
static TLS_NEXT: AtomicU32 = AtomicU32::new(0);
static LAST_ERROR: AtomicU32 = AtomicU32::new(0);

// SYSTEM_INFO structure layout (x64):
//   0x00: WORD wProcessorArchitecture
//   0x02: WORD wReserved
//   0x04: DWORD dwPageSize
//   0x08: LPVOID lpMinimumApplicationAddress
//   0x10: LPVOID lpMaximumApplicationAddress
//   0x18: DWORD_PTR dwActiveProcessorMask
//   0x20: DWORD dwNumberOfProcessors
//   0x24: DWORD dwProcessorType
//   0x28: DWORD dwAllocationGranularity
//   0x2C: WORD wProcessorLevel
//   0x2E: WORD wProcessorRevision
#[repr(C)]
struct SYSTEM_INFO {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    min_app_address: u64,
    max_app_address: u64,
    active_processor_mask: u64,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

// Helper functions for file handle management (outside macro to avoid extern convention)
fn get_handle_map() -> &'static RwLock<HashMap<usize, i32>> {
    HANDLE_MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

fn alloc_handle(fd: i32) -> usize {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst) as usize;
    get_handle_map().write().unwrap().insert(handle, fd);
    handle
}

fn get_fd(handle: usize) -> Option<i32> {
    get_handle_map().read().unwrap().get(&handle).copied()
}

fn free_handle(handle: usize) -> Option<i32> {
    get_handle_map().write().unwrap().remove(&handle)
}

fn get_mmap_map() -> &'static RwLock<HashMap<usize, (usize, usize)>> {
    MMAP_MAP.get_or_init(|| RwLock::new(HashMap::new()))
}

import_fn! {
    // ============ KERNEL32 - process ============

    fn GetCurrentProcess() -> *mut c_void {
        trace_call!("kernel32!GetCurrentProcess");
        -1isize as *mut c_void
    }

    fn TerminateProcess(_process: *mut c_void, exit_code: u32) -> i32 {
        trace_call!("kernel32!TerminateProcess", "exit_code={}", exit_code);
        std::process::exit(exit_code as i32);
    }

    fn UnhandledExceptionFilter(_exception_info: *mut c_void) -> i32 {
        trace_call!("kernel32!UnhandledExceptionFilter");
        panic!("kernel32!UnhandledExceptionFilter not implemented");
    }

    fn SetUnhandledExceptionFilter(filter: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!SetUnhandledExceptionFilter");
        let old = EXCEPTION_FILTER.swap(filter as u64, Ordering::SeqCst);
        old as *mut c_void
    }

    fn IsDebuggerPresent() -> i32 {
        trace_call!("kernel32!IsDebuggerPresent");
        0
    }

    fn IsProcessorFeaturePresent(feature: u32) -> i32 {
        trace_call!("kernel32!IsProcessorFeaturePresent", "feature={}", feature);
        match feature {
            10 => 1, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
            23 => 1, // PF_FASTFAIL_AVAILABLE
            _ => 0,
        }
    }

    fn GetVersion() -> u32 {
        trace_call!("kernel32!GetVersion");
        // 6.2 build 9200
        (9200 << 16) | (2 << 8) | 6
    }

    // ============ KERNEL32 - file (narrow) ============

    fn CreateFileA(
        lpFileName: *const i8,
        dwDesiredAccess: u32,
        _dwShareMode: u32,
        _lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        _dwFlagsAndAttributes: u32,
        _hTemplateFile: *mut c_void,
    ) -> *mut c_void {
        trace_call!("kernel32!CreateFileA", "file={}", {
            if lpFileName.is_null() {
                "<null>".to_string()
            } else {
                CStr::from_ptr(lpFileName).to_string_lossy().to_string()
            }
        });

        let mut flags = 0;
        let read = dwDesiredAccess & 0x80000000 != 0;
        let write = dwDesiredAccess & 0x40000000 != 0;

        if read && write {
            flags |= libc::O_RDWR;
        } else if write {
            flags |= libc::O_WRONLY;
        } else {
            flags |= libc::O_RDONLY;
        }

        match dwCreationDisposition {
            1 => flags |= libc::O_CREAT | libc::O_EXCL,
            2 => flags |= libc::O_CREAT | libc::O_TRUNC,
            3 => {}
            4 => flags |= libc::O_CREAT,
            5 => flags |= libc::O_TRUNC,
            _ => {}
        }

        let fd = libc::open(lpFileName, flags, 0o644);
        if fd < 0 {
            (-1isize) as *mut c_void
        } else {
            alloc_handle(fd) as *mut c_void
        }
    }

    fn GetFullPathNameA(
        lpFileName: *const i8,
        nBufferLength: u32,
        lpBuffer: *mut i8,
        _lpFilePart: *mut *mut i8,
    ) -> u32 {
        trace_call!("kernel32!GetFullPathNameA", "file={}", {
            if lpFileName.is_null() {
                "<null>".to_string()
            } else {
                CStr::from_ptr(lpFileName).to_string_lossy().to_string()
            }
        });

        if lpFileName.is_null() || lpBuffer.is_null() {
            return 0;
        }

        let len = libc::strlen(lpFileName);
        if len < nBufferLength as usize {
            libc::strcpy(lpBuffer, lpFileName);
            len as u32
        } else {
            0
        }
    }

    // ============ KERNEL32 - memory ============

    // Windows reserves address space and commits pages inside it as separate steps, and expects a
    // commit to land at the address asked for. A reservation is mapped with no access, a commit
    // inside one turns access on in place, a decommit discards the pages and turns access off, and a
    // release unmaps the whole reservation. MEM_COMMIT 0x1000, MEM_RESERVE 0x2000, MEM_DECOMMIT
    // 0x4000, MEM_RELEASE 0x8000.
    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void {
        trace_call!(
            "kernel32!VirtualAlloc",
            "addr={:p}, size={}, type=0x{:x}, prot=0x{:x}",
            lpAddress,
            dwSize,
            flAllocationType,
            flProtect
        );
        let prot = match flProtect {
            0x01 => libc::PROT_NONE,
            0x04 => libc::PROT_READ | libc::PROT_WRITE,
            0x02 => libc::PROT_READ,
            0x10 => libc::PROT_READ | libc::PROT_EXEC,
            0x20 => libc::PROT_READ | libc::PROT_EXEC,
            0x40 => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            _ => libc::PROT_READ | libc::PROT_WRITE,
        };
        let page = 4096usize;

        // committing pages of an existing reservation
        if !lpAddress.is_null() && flAllocationType & 0x2000 == 0 {
            let start = lpAddress as usize & !(page - 1);
            let end = (lpAddress as usize + dwSize + page - 1) & !(page - 1);
            let inside = virt_table()
                .lock()
                .unwrap()
                .iter()
                .any(|(&base, &size)| start >= base && end <= base + size);
            if !inside || libc::mprotect(start as *mut c_void, end - start, prot) != 0 {
                trace_call!("kernel32!VirtualAlloc failed", "commit outside a reservation: {:p} size {}", lpAddress, dwSize);
                return std::ptr::null_mut();
            }
            return start as *mut c_void;
        }

        // a new reservation, committed or not; Windows places it on a 64 KiB boundary, which an
        // address the caller asks for already is
        let reserve_only = flAllocationType & 0x1000 == 0;
        let size = (dwSize + page - 1) & !(page - 1);
        let flags = libc::MAP_PRIVATE
            | libc::MAP_ANONYMOUS
            | if reserve_only { libc::MAP_NORESERVE } else { 0 }
            | if lpAddress.is_null() { 0 } else { libc::MAP_FIXED_NOREPLACE };
        let prot = if reserve_only { libc::PROT_NONE } else { prot };
        let ptr = if lpAddress.is_null() {
            // map 64 KiB more than asked, then trim to a 64 KiB boundary
            let granularity = 0x10000usize;
            let raw = libc::mmap(std::ptr::null_mut(), size + granularity, prot, flags, -1, 0);
            if raw == libc::MAP_FAILED {
                return std::ptr::null_mut();
            }
            let aligned = (raw as usize + granularity - 1) & !(granularity - 1);
            let head = aligned - raw as usize;
            if head > 0 {
                libc::munmap(raw, head);
            }
            let tail = granularity - head;
            if tail > 0 {
                libc::munmap((aligned + size) as *mut c_void, tail);
            }
            aligned as *mut c_void
        } else {
            libc::mmap(lpAddress, size, prot, flags, -1, 0)
        };
        if ptr == libc::MAP_FAILED {
            return std::ptr::null_mut();
        }
        virt_table().lock().unwrap().insert(ptr as usize, size);
        ptr
    }

    fn VirtualFree(
        lpAddress: *mut c_void,
        dwSize: usize,
        dwFreeType: u32,
    ) -> i32 {
        trace_call!(
            "kernel32!VirtualFree",
            "addr={:p}, size={}, type=0x{:x}",
            lpAddress,
            dwSize,
            dwFreeType
        );
        if lpAddress.is_null() {
            return 0;
        }
        let page = 4096usize;
        if dwFreeType & 0x4000 != 0 {
            // decommit: the range, or the whole reservation when the size is 0
            let start = lpAddress as usize & !(page - 1);
            let size = if dwSize == 0 {
                match virt_table().lock().unwrap().get(&start) {
                    Some(&size) => size,
                    None => return 0,
                }
            } else {
                (lpAddress as usize + dwSize + page - 1 - start) & !(page - 1)
            };
            libc::madvise(start as *mut c_void, size, libc::MADV_DONTNEED);
            return (libc::mprotect(start as *mut c_void, size, libc::PROT_NONE) == 0) as i32;
        }
        // release: always the whole reservation, from its base
        let Some(size) = virt_table().lock().unwrap().remove(&(lpAddress as usize)) else {
            return 0;
        };
        (libc::munmap(lpAddress, size) == 0) as i32
    }

    fn GetProcessHeap() -> *mut c_void {
        trace_call!("kernel32!GetProcessHeap");
        PROCESS_HEAP as *mut c_void
    }

    fn HeapCreate(
        _flOptions: u32,
        _dwInitialSize: usize,
        _dwMaximumSize: usize,
    ) -> *mut c_void {
        trace_call!("kernel32!HeapCreate");
        HEAP_NEXT.fetch_add(1, Ordering::Relaxed) as *mut c_void
    }

    fn HeapDestroy(hHeap: *mut c_void) -> i32 {
        trace_call!("kernel32!HeapDestroy", "hHeap={:p}", hHeap);
        let removed = heap_table().lock().unwrap().remove(&(hHeap as u32));
        if let Some(ptrs) = removed {
            for p in ptrs {
                super::heap::free(p as *mut c_void);
            }
        }
        1
    }

    fn HeapAlloc(
        hHeap: *mut c_void,
        dwFlags: u32,
        dwBytes: usize,
    ) -> *mut c_void {
        trace_call!("kernel32!HeapAlloc", "size={}", dwBytes);
        // HEAP_ZERO_MEMORY 0x08
        let ptr = super::heap::alloc(dwBytes, dwFlags & 0x08 != 0);
        if !ptr.is_null() {
            heap_table()
                .lock()
                .unwrap()
                .entry(hHeap as u32)
                .or_default()
                .push(ptr as usize);
        }
        ptr
    }

    fn HeapReAlloc(
        hHeap: *mut c_void,
        dwFlags: u32,
        lpMem: *mut c_void,
        dwBytes: usize,
    ) -> *mut c_void {
        trace_call!(
            "kernel32!HeapReAlloc",
            "ptr={:p}, size={}",
            lpMem,
            dwBytes
        );
        if !lpMem.is_null() {
            let mut t = heap_table().lock().unwrap();
            if let Some(v) = t.get_mut(&(hHeap as u32))
                && let Some(pos) = v.iter().rposition(|&p| p == lpMem as usize) {
                    v.swap_remove(pos);
                }
        }
        // Windows keeps the contents and zeroes only the bytes a grown block gains; with
        // HEAP_REALLOC_IN_PLACE_ONLY (0x10) it fails rather than move the block
        if dwFlags & 0x10 != 0 && !lpMem.is_null() && dwBytes > super::heap::size(lpMem) {
            heap_table().lock().unwrap().entry(hHeap as u32).or_default().push(lpMem as usize);
            return std::ptr::null_mut();
        }
        let new_ptr = super::heap::realloc(lpMem, dwBytes, dwFlags & 0x08 != 0);
        if !new_ptr.is_null() {
            heap_table()
                .lock()
                .unwrap()
                .entry(hHeap as u32)
                .or_default()
                .push(new_ptr as usize);
        }
        new_ptr
    }

    fn HeapFree(hHeap: *mut c_void, _dwFlags: u32, lpMem: *mut c_void) -> i32 {
        trace_call!("kernel32!HeapFree", "ptr={:p}", lpMem);
        if !lpMem.is_null() {
            let mut t = heap_table().lock().unwrap();
            if let Some(v) = t.get_mut(&(hHeap as u32))
                && let Some(pos) = v.iter().rposition(|&p| p == lpMem as usize) {
                    v.swap_remove(pos);
                }
            super::heap::free(lpMem);
        }
        1
    }

    // The size the block was asked for, as Windows reports it; (SIZE_T)-1 for a block it does not know
    fn HeapSize(_hHeap: *mut c_void, _dwFlags: u32, lpMem: *const c_void) -> usize {
        trace_call!("kernel32!HeapSize");
        if lpMem.is_null() { usize::MAX } else { super::heap::size(lpMem as *mut c_void) }
    }

    fn LocalAlloc(uFlags: u32, uBytes: usize) -> *mut c_void {
        trace_call!("kernel32!LocalAlloc", "size={}", uBytes);
        // LMEM_ZEROINIT 0x40
        super::heap::alloc(uBytes, uFlags & 0x40 != 0)
    }

    fn LocalFree(hMem: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!LocalFree", "ptr={:p}", hMem);
        super::heap::free(hMem);
        std::ptr::null_mut()
    }

    // ============ KERNEL32 - file ============

    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        _dwShareMode: u32,
        _lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        _dwFlagsAndAttributes: u32,
        _hTemplateFile: *mut c_void,
    ) -> *mut c_void {
        let path = wstr_to_string(lpFileName);
        trace_call!(
            "kernel32!CreateFileW",
            "file={}",
            String::from_utf8_lossy(&path[..path.len() - 1])
        );

        let mut flags = 0;
        let read = dwDesiredAccess & 0x80000000 != 0;
        let write = dwDesiredAccess & 0x40000000 != 0;

        if read && write {
            flags |= libc::O_RDWR;
        } else if write {
            flags |= libc::O_WRONLY;
        } else {
            flags |= libc::O_RDONLY;
        }

        match dwCreationDisposition {
            1 => flags |= libc::O_CREAT | libc::O_EXCL,
            2 => flags |= libc::O_CREAT | libc::O_TRUNC,
            3 => {}
            4 => flags |= libc::O_CREAT,
            5 => flags |= libc::O_TRUNC,
            _ => {}
        }

        let fd = libc::open(path.as_ptr() as *const i8, flags, 0o644);

        if fd < 0 {
            (-1isize) as *mut c_void
        } else {
            alloc_handle(fd) as *mut c_void
        }
    }

    fn ReadFile(
        hFile: *mut c_void,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: u32,
        lpNumberOfBytesRead: *mut u32,
        _lpOverlapped: *mut c_void,
    ) -> i32 {
        trace_call!("kernel32!ReadFile", "bytes={}", nNumberOfBytesToRead);
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let result = libc::read(fd, lpBuffer, nNumberOfBytesToRead as usize);
            if result >= 0 {
                if !lpNumberOfBytesRead.is_null() {
                    *lpNumberOfBytesRead = result as u32;
                }
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    fn WriteFile(
        hFile: *mut c_void,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        _lpOverlapped: *mut c_void,
    ) -> i32 {
        trace_call!("kernel32!WriteFile", "bytes={}", nNumberOfBytesToWrite);
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let result = libc::write(fd, lpBuffer, nNumberOfBytesToWrite as usize);
            if result >= 0 {
                if !lpNumberOfBytesWritten.is_null() {
                    *lpNumberOfBytesWritten = result as u32;
                }
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    fn CloseHandle(hObject: *mut c_void) -> i32 {
        trace_call!("kernel32!CloseHandle", "handle={:p}", hObject);
        let handle = hObject as usize;
        if get_events().lock().unwrap().remove(&handle).is_some() {
            return 1;
        }
        if let Some(fd) = free_handle(handle) {
            libc::close(fd);
            1
        } else {
            1
        }
    }

    fn GetFileSize(hFile: *mut c_void, lpFileSizeHigh: *mut u32) -> u32 {
        trace_call!("kernel32!GetFileSize");
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let mut stat: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut stat) == 0 {
                if !lpFileSizeHigh.is_null() {
                    *lpFileSizeHigh = (stat.st_size >> 32) as u32;
                }
                stat.st_size as u32
            } else {
                0xFFFFFFFF
            }
        } else {
            0xFFFFFFFF
        }
    }

    fn GetFileSizeEx(hFile: *mut c_void, lpFileSize: *mut i64) -> i32 {
        trace_call!("kernel32!GetFileSizeEx");
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let mut stat: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut stat) == 0 {
                *lpFileSize = stat.st_size;
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    fn GetFileType(_hFile: *mut c_void) -> u32 {
        trace_call!("kernel32!GetFileType");
        1
    }

    fn SetFilePointer(
        hFile: *mut c_void,
        lDistanceToMove: i32,
        lpDistanceToMoveHigh: *mut i32,
        dwMoveMethod: u32,
    ) -> u32 {
        trace_call!("kernel32!SetFilePointer");
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let offset = if lpDistanceToMoveHigh.is_null() {
                lDistanceToMove as i64
            } else {
                ((*lpDistanceToMoveHigh as i64) << 32) | (lDistanceToMove as u32 as i64)
            };

            let whence = match dwMoveMethod {
                0 => libc::SEEK_SET,
                1 => libc::SEEK_CUR,
                2 => libc::SEEK_END,
                _ => libc::SEEK_SET,
            };

            let result = libc::lseek(fd, offset, whence);
            if result >= 0 {
                if !lpDistanceToMoveHigh.is_null() {
                    *lpDistanceToMoveHigh = (result >> 32) as i32;
                }
                result as u32
            } else {
                0xFFFFFFFF
            }
        } else {
            0xFFFFFFFF
        }
    }

    fn SetFilePointerEx(
        hFile: *mut c_void,
        liDistanceToMove: i64,
        lpNewFilePointer: *mut i64,
        dwMoveMethod: u32,
    ) -> i32 {
        trace_call!("kernel32!SetFilePointerEx");
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let whence = match dwMoveMethod {
                0 => libc::SEEK_SET,
                1 => libc::SEEK_CUR,
                2 => libc::SEEK_END,
                _ => libc::SEEK_SET,
            };

            let result = libc::lseek(fd, liDistanceToMove, whence);
            if result >= 0 {
                if !lpNewFilePointer.is_null() {
                    *lpNewFilePointer = result;
                }
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    fn SetEndOfFile(hFile: *mut c_void) -> i32 {
        trace_call!("kernel32!SetEndOfFile");
        let handle = hFile as usize;
        if let Some(fd) = get_fd(handle) {
            let pos = libc::lseek(fd, 0, libc::SEEK_CUR);
            if pos >= 0 && libc::ftruncate(fd, pos) == 0 {
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    fn CopyFileExW(
        lpExistingFileName: *const u16,
        lpNewFileName: *const u16,
        _lpProgressRoutine: *const c_void,
        _lpData: *mut c_void,
        _pbCancel: *mut i32,
        dwCopyFlags: u32,
    ) -> i32 {
        trace_call!("kernel32!CopyFileExW", "flags={:#x}", dwCopyFlags);
        use std::os::unix::ffi::OsStrExt;
        let src = wstr_to_string(lpExistingFileName);
        let dst = wstr_to_string(lpNewFileName);
        let src = std::path::Path::new(std::ffi::OsStr::from_bytes(&src[..src.len() - 1]));
        let dst = std::path::Path::new(std::ffi::OsStr::from_bytes(&dst[..dst.len() - 1]));

        // COPY_FILE_FAIL_IF_EXISTS
        if dwCopyFlags & 1 != 0 && dst.exists() {
            LAST_ERROR.store(80, Ordering::SeqCst); // ERROR_FILE_EXISTS
            return 0;
        }
        match std::fs::copy(src, dst) {
            Ok(_) => 1,
            Err(e) => {
                let code = match e.kind() {
                    std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                    std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                    _ => 31,                                   // ERROR_GEN_FAILURE
                };
                LAST_ERROR.store(code, Ordering::SeqCst);
                0
            }
        }
    }

    fn DeleteFileW(lpFileName: *const u16) -> i32 {
        trace_call!("kernel32!DeleteFileW");
        let path = wstr_to_string(lpFileName);
        if libc::unlink(path.as_ptr() as *const i8) == 0 {
            1
        } else {
            0
        }
    }

    fn GetFileAttributesW(lpFileName: *const u16) -> u32 {
        trace_call!("kernel32!GetFileAttributesW");
        let path = wstr_to_string(lpFileName);
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::stat(path.as_ptr() as *const i8, &mut stat) == 0 {
            let mut attrs = 0u32;
            if stat.st_mode & libc::S_IFDIR != 0 {
                attrs |= 0x10;
            }
            if attrs == 0 {
                attrs = 0x80;
            }
            attrs
        } else {
            0xFFFFFFFF
        }
    }

    fn SetFileAttributesW(
        _lpFileName: *const u16,
        _dwFileAttributes: u32,
    ) -> i32 {
        trace_call!("kernel32!SetFileAttributesW");
        1
    }

    fn GetFullPathNameW(
        lpFileName: *const u16,
        nBufferLength: u32,
        lpBuffer: *mut u16,
        _lpFilePart: *mut *mut u16,
    ) -> u32 {
        trace_call!("kernel32!GetFullPathNameW");
        let mut len = 0;
        while *lpFileName.add(len) != 0 {
            len += 1;
        }
        if len < nBufferLength as usize {
            for i in 0..=len {
                *lpBuffer.add(i) = *lpFileName.add(i);
            }
            len as u32
        } else {
            0
        }
    }

    // ============ KERNEL32 - memory mapped files ============

    fn CreateFileMappingW(
        hFile: *mut c_void,
        _lpFileMappingAttributes: *mut c_void,
        _flProtect: u32,
        dwMaximumSizeHigh: u32,
        dwMaximumSizeLow: u32,
        _lpName: *const u16,
    ) -> *mut c_void {
        trace_call!("kernel32!CreateFileMappingW");
        let handle = hFile as usize;
        let size = ((dwMaximumSizeHigh as u64) << 32) | dwMaximumSizeLow as u64;

        if let Some(fd) = get_fd(handle) {
            let mapping_handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst) as usize;
            get_mmap_map()
                .write()
                .unwrap()
                .insert(mapping_handle, (fd as usize, size as usize));
            mapping_handle as *mut c_void
        } else {
            std::ptr::null_mut()
        }
    }

    fn MapViewOfFile(
        hFileMappingObject: *mut c_void,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: usize,
    ) -> *mut c_void {
        trace_call!("kernel32!MapViewOfFile");
        MapViewOfFileEx(
            hFileMappingObject,
            dwDesiredAccess,
            dwFileOffsetHigh,
            dwFileOffsetLow,
            dwNumberOfBytesToMap,
            std::ptr::null_mut(),
        )
    }

    fn MapViewOfFileEx(
        hFileMappingObject: *mut c_void,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: usize,
        lpBaseAddress: *mut c_void,
    ) -> *mut c_void {
        trace_call!("kernel32!MapViewOfFileEx");
        let mapping_handle = hFileMappingObject as usize;

        if let Some((fd, size)) = get_mmap_map().read().unwrap().get(&mapping_handle).copied() {
            let offset = ((dwFileOffsetHigh as i64) << 32) | dwFileOffsetLow as i64;
            let len = if dwNumberOfBytesToMap == 0 {
                size
            } else {
                dwNumberOfBytesToMap
            };

            let prot = if dwDesiredAccess & 0x02 != 0 {
                libc::PROT_READ | libc::PROT_WRITE
            } else {
                libc::PROT_READ
            };

            let ptr = libc::mmap(
                lpBaseAddress,
                len,
                prot,
                libc::MAP_SHARED,
                fd as i32,
                offset,
            );

            if ptr == libc::MAP_FAILED {
                std::ptr::null_mut()
            } else {
                ptr
            }
        } else {
            std::ptr::null_mut()
        }
    }

    fn UnmapViewOfFile(_lpBaseAddress: *const c_void) -> i32 {
        trace_call!("kernel32!UnmapViewOfFile");
        1
    }

    fn FlushViewOfFile(
        lpBaseAddress: *const c_void,
        dwNumberOfBytesToFlush: usize,
    ) -> i32 {
        trace_call!("kernel32!FlushViewOfFile");
        if libc::msync(
            lpBaseAddress as *mut c_void,
            dwNumberOfBytesToFlush,
            libc::MS_SYNC,
        ) == 0
        {
            1
        } else {
            0
        }
    }

    fn DeviceIoControl(
        _hDevice: *mut c_void,
        _dwIoControlCode: u32,
        _lpInBuffer: *mut c_void,
        _nInBufferSize: u32,
        _lpOutBuffer: *mut c_void,
        _nOutBufferSize: u32,
        _lpBytesReturned: *mut u32,
        _lpOverlapped: *mut c_void,
    ) -> i32 {
        trace_call!("kernel32!DeviceIoControl");
        panic!("kernel32!DeviceIoControl not implemented");
    }

    // ============ KERNEL32 - sync ============

    fn InitializeCriticalSection(lpCriticalSection: *mut c_void) {
        trace_call!("kernel32!InitializeCriticalSection");
        // a thread may enter a critical section it already holds
        let cs = lpCriticalSection as *mut libc::pthread_mutex_t;
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        libc::pthread_mutexattr_init(&mut attr);
        libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        libc::pthread_mutex_init(cs, &attr);
        libc::pthread_mutexattr_destroy(&mut attr);
    }

    fn InitializeCriticalSectionAndSpinCount(
        lpCriticalSection: *mut c_void,
        _dwSpinCount: u32,
    ) -> i32 {
        trace_call!("kernel32!InitializeCriticalSectionAndSpinCount");
        InitializeCriticalSection(lpCriticalSection);
        1
    }

    fn DeleteCriticalSection(lpCriticalSection: *mut c_void) {
        trace_call!("kernel32!DeleteCriticalSection");
        let cs = lpCriticalSection as *mut libc::pthread_mutex_t;
        libc::pthread_mutex_destroy(cs);
    }

    fn EnterCriticalSection(lpCriticalSection: *mut c_void) {
        trace_call!("kernel32!EnterCriticalSection");
        let cs = lpCriticalSection as *mut libc::pthread_mutex_t;
        libc::pthread_mutex_lock(cs);
    }

    fn LeaveCriticalSection(lpCriticalSection: *mut c_void) {
        trace_call!("kernel32!LeaveCriticalSection");
        let cs = lpCriticalSection as *mut libc::pthread_mutex_t;
        libc::pthread_mutex_unlock(cs);
    }

    fn Sleep(dwMilliseconds: u32) {
        trace_call!("kernel32!Sleep", "ms={}", dwMilliseconds);
        libc::usleep(dwMilliseconds * 1000);
    }

    // ============ KERNEL32 - TLS ============

    fn get_tls_slots() -> &'static RwLock<HashMap<u32, libc::pthread_key_t>> {
        TLS_SLOTS.get_or_init(|| RwLock::new(HashMap::new()))
    }

    fn TlsAlloc() -> u32 {
        trace_call!("kernel32!TlsAlloc");
        let mut key: libc::pthread_key_t = 0;
        if libc::pthread_key_create(&mut key, None) == 0 {
            let slot = TLS_NEXT.fetch_add(1, Ordering::SeqCst);
            get_tls_slots().write().unwrap().insert(slot, key);
            slot
        } else {
            0xFFFFFFFF
        }
    }

    fn TlsFree(dwTlsIndex: u32) -> i32 {
        trace_call!("kernel32!TlsFree");
        if let Some(key) = get_tls_slots().write().unwrap().remove(&dwTlsIndex) {
            libc::pthread_key_delete(key);
            1
        } else {
            0
        }
    }

    fn TlsGetValue(dwTlsIndex: u32) -> *mut c_void {
        trace_call!("kernel32!TlsGetValue");
        if let Some(&key) = get_tls_slots().read().unwrap().get(&dwTlsIndex) {
            libc::pthread_getspecific(key)
        } else {
            std::ptr::null_mut()
        }
    }

    fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: *mut c_void) -> i32 {
        trace_call!("kernel32!TlsSetValue");
        if let Some(&key) = get_tls_slots().read().unwrap().get(&dwTlsIndex) {
            if libc::pthread_setspecific(key, lpTlsValue) == 0 {
                1
            } else {
                0
            }
        } else {
            0
        }
    }

    // ============ KERNEL32 - misc ============

    fn GetLastError() -> u32 {
        trace_call!("kernel32!GetLastError");
        LAST_ERROR.load(Ordering::SeqCst)
    }

    fn SetLastError(dwErrCode: u32) {
        trace_call!("kernel32!SetLastError", "code={}", dwErrCode);
        LAST_ERROR.store(dwErrCode, Ordering::SeqCst);
    }

    fn GetCurrentProcessId() -> u32 {
        trace_call!("kernel32!GetCurrentProcessId");
        libc::getpid() as u32
    }

    fn GetCurrentThreadId() -> u32 {
        trace_call!("kernel32!GetCurrentThreadId");
        libc::pthread_self() as u32
    }

    fn GetTickCount() -> u32 {
        trace_call!("kernel32!GetTickCount");
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        ((ts.tv_sec * 1000) + (ts.tv_nsec / 1_000_000)) as u32
    }

    fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i32 {
        trace_call!("kernel32!QueryPerformanceCounter");
        let mut ts: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            *lpPerformanceCount = ts.tv_sec * 1_000_000_000 + ts.tv_nsec;
            1
        } else {
            0
        }
    }

    fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut u64) {
        trace_call!("kernel32!GetSystemTimeAsFileTime");
        let mut tv: libc::timeval = std::mem::zeroed();
        libc::gettimeofday(&mut tv, std::ptr::null_mut());
        let epoch_diff = 116444736000000000u64;
        *lpSystemTimeAsFileTime =
            ((tv.tv_sec as u64) * 10_000_000 + (tv.tv_usec as u64) * 10) + epoch_diff;
    }

    fn GetSystemInfo(lpSystemInfo: *mut c_void) {
        trace_call!("kernel32!GetSystemInfo");
        let info = lpSystemInfo as *mut SYSTEM_INFO;
        (*info).processor_architecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
        (*info).reserved = 0;
        (*info).page_size = 4096;
        (*info).min_app_address = 0x10000;
        (*info).max_app_address = 0x7FFFFFFEFFFF;
        (*info).active_processor_mask = 0xFF;
        (*info).number_of_processors = 8;
        (*info).processor_type = 8664; // PROCESSOR_AMD_X8664
        (*info).allocation_granularity = 65536;
        (*info).processor_level = 6;
        (*info).processor_revision = 0;
    }

    fn OutputDebugStringA(lpOutputString: *const i8) {
        trace_call!("kernel32!OutputDebugStringA");
        if !lpOutputString.is_null() {
            eprintln!(
                "[DEBUG] {}",
                CStr::from_ptr(lpOutputString).to_string_lossy()
            );
        }
    }

    fn DisableThreadLibraryCalls(_hLibModule: *mut c_void) -> i32 {
        trace_call!("kernel32!DisableThreadLibraryCalls");
        1
    }

    fn FreeLibrary(_hLibModule: *mut c_void) -> i32 {
        trace_call!("kernel32!FreeLibrary");
        1
    }

    fn LoadLibraryExW(
        lpLibFileName: *const u16,
        _hFile: *mut c_void,
        _dwFlags: u32,
    ) -> *mut c_void {
        let name = wide_to_string(lpLibFileName);
        trace_call!("kernel32!LoadLibraryExW", "name={}", name);
        module_handle(&name, true)
    }

    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void {
        let name = wide_to_string(lpLibFileName);
        trace_call!("kernel32!LoadLibraryW", "name={}", name);
        module_handle(&name, true)
    }

    fn LoadLibraryA(lpLibFileName: *const i8) -> *mut c_void {
        let name = CStr::from_ptr(lpLibFileName).to_string_lossy().into_owned();
        trace_call!("kernel32!LoadLibraryA", "name={}", name);
        module_handle(&name, true)
    }

    // Resolves a name in a system DLL that GetModuleHandleW handed out, through the same shims its
    // imports use. A function there is no shim for is reported missing, which the DLL can handle
    fn GetProcAddress(
        hModule: *mut c_void,
        lpProcName: *const i8,
    ) -> *mut c_void {
        // a value below 0x10000 is an ordinal, not a name
        if (lpProcName as usize) < 0x10000 {
            trace_call!("kernel32!GetProcAddress", "ordinal={}", lpProcName as usize);
            return crate::module::find_by_handle(hModule as usize)
                .and_then(|m| m.export_by_ordinal(lpProcName as u32))
                .map_or(std::ptr::null_mut(), |a| a as *mut c_void);
        }
        let name = CStr::from_ptr(lpProcName).to_string_lossy();
        trace_call!("kernel32!GetProcAddress", "name={}", name);
        if let Some(module) = crate::module::find_by_handle(hModule as usize) {
            return module.export(&name).map_or(std::ptr::null_mut(), |a| a as *mut c_void);
        }
        let Some(dll) = get_modules().lock().unwrap().get(&(hModule as usize)).cloned() else {
            return std::ptr::null_mut();
        };
        crate::linux_loader::resolve_import(&dll, &name).map_or(std::ptr::null_mut(), |a| a as *mut c_void)
    }

    fn GetModuleFileNameA(
        _hModule: *mut c_void,
        _lpFilename: *mut i8,
        _nSize: u32,
    ) -> u32 {
        trace_call!("kernel32!GetModuleFileNameA");
        // Return 0: no module filename available
        0
    }

    fn GetEnvironmentVariableA(
        lpName: *const i8,
        lpBuffer: *mut i8,
        nSize: u32,
    ) -> u32 {
        trace_call!("kernel32!GetEnvironmentVariableA");
        let val = libc::getenv(lpName);
        if val.is_null() {
            0
        } else {
            let len = libc::strlen(val);
            if len < nSize as usize {
                libc::strcpy(lpBuffer, val);
                len as u32
            } else {
                (len + 1) as u32
            }
        }
    }

    fn ExpandEnvironmentStringsW(
        lpSrc: *const u16,
        lpDst: *mut u16,
        nSize: u32,
    ) -> u32 {
        trace_call!("kernel32!ExpandEnvironmentStringsW");
        let mut len = 0;
        while *lpSrc.add(len) != 0 {
            len += 1;
        }
        if len < nSize as usize {
            for i in 0..=len {
                *lpDst.add(i) = *lpSrc.add(i);
            }
            (len + 1) as u32
        } else {
            0
        }
    }

    fn MultiByteToWideChar(
        _CodePage: u32,
        _dwFlags: u32,
        lpMultiByteStr: *const i8,
        cbMultiByte: i32,
        lpWideCharStr: *mut u16,
        cchWideChar: i32,
    ) -> i32 {
        trace_call!("kernel32!MultiByteToWideChar");
        let len = if cbMultiByte < 0 {
            libc::strlen(lpMultiByteStr) as i32 + 1
        } else {
            cbMultiByte
        };

        if cchWideChar == 0 {
            return len;
        }

        let copy_len = len.min(cchWideChar);
        for i in 0..copy_len as usize {
            *lpWideCharStr.add(i) = *lpMultiByteStr.add(i) as u8 as u16;
        }
        copy_len
    }

    fn WideCharToMultiByte(
        _CodePage: u32,
        _dwFlags: u32,
        lpWideCharStr: *const u16,
        cchWideChar: i32,
        lpMultiByteStr: *mut i8,
        cbMultiByte: i32,
        _lpDefaultChar: *const i8,
        _lpUsedDefaultChar: *mut i32,
    ) -> i32 {
        trace_call!("kernel32!WideCharToMultiByte");
        let len = if cchWideChar < 0 {
            let mut l = 0;
            while *lpWideCharStr.add(l) != 0 {
                l += 1;
            }
            l as i32 + 1
        } else {
            cchWideChar
        };

        if cbMultiByte == 0 {
            return len;
        }

        let copy_len = len.min(cbMultiByte);
        for i in 0..copy_len as usize {
            let c = *lpWideCharStr.add(i);
            *lpMultiByteStr.add(i) = if c < 128 { c as i8 } else { b'?' as i8 };
        }
        copy_len
    }

    fn LCMapStringW(
        _Locale: u32,
        dwMapFlags: u32,
        lpSrcStr: *const u16,
        cchSrc: i32,
        lpDestStr: *mut u16,
        cchDest: i32,
    ) -> i32 {
        trace_call!("kernel32!LCMapStringW");
        let len = if cchSrc < 0 {
            let mut l = 0;
            while *lpSrcStr.add(l) != 0 {
                l += 1;
            }
            l as i32 + 1
        } else {
            cchSrc
        };

        if cchDest == 0 {
            return len;
        }

        let copy_len = len.min(cchDest);
        for i in 0..copy_len as usize {
            let c = *lpSrcStr.add(i);
            *lpDestStr.add(i) = if dwMapFlags & 0x100 != 0 {
                ascii_lower(c as u32) as u16
            } else if dwMapFlags & 0x200 != 0 {
                ascii_upper(c as u32) as u16
            } else {
                c
            };
        }
        copy_len
    }

    fn lstrcmpiA(lpString1: *const i8, lpString2: *const i8) -> i32 {
        trace_call!("kernel32!lstrcmpiA");
        libc::strcasecmp(lpString1, lpString2)
    }
}

// ============ kernel32 - events ============
// An event is a flag and a condition variable, kept under a handle number from the same counter as
// file handles

struct Event {
    signalled: Mutex<bool>,
    changed: std::sync::Condvar,
    manual_reset: bool,
}

fn wide_to_string(s: *const u16) -> String {
    let name = unsafe { wstr_to_string(s) };
    String::from_utf8_lossy(&name[..name.len() - 1]).into_owned()
}

// A DLL that is loaded has its base address as its handle, as on Windows; with load, a DLL found
// beside a loaded one is loaded first. Every system DLL is loaded as far as the DLLs can tell, and
// its functions are the shims. Any other DLL is missing.
fn module_handle(name: &str, load: bool) -> *mut c_void {
    let found = if load {
        crate::module::find_or_load(name)
    } else {
        crate::module::find(name)
    };
    if let Some(module) = found {
        return module.base as *mut c_void;
    }
    if !crate::module::is_system(name) {
        LAST_ERROR.store(126, Ordering::SeqCst); // ERROR_MOD_NOT_FOUND
        return std::ptr::null_mut();
    }
    let lower = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_lowercase();
    let dll = if lower.ends_with(".dll") {
        lower
    } else {
        format!("{lower}.dll")
    };
    let mut modules = get_modules().lock().unwrap();
    if let Some((&handle, _)) = modules.iter().find(|(_, n)| **n == dll) {
        return handle as *mut c_void;
    }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst) as usize;
    modules.insert(handle, dll);
    handle as *mut c_void
}

// The system DLLs GetModuleHandleW has handed out a handle for, by handle
static MODULES: OnceLock<Mutex<HashMap<usize, String>>> = OnceLock::new();

fn get_modules() -> &'static Mutex<HashMap<usize, String>> {
    MODULES.get_or_init(|| Mutex::new(HashMap::new()))
}

static EVENTS: OnceLock<Mutex<HashMap<usize, std::sync::Arc<Event>>>> = OnceLock::new();

fn get_events() -> &'static Mutex<HashMap<usize, std::sync::Arc<Event>>> {
    EVENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_event(handle: *mut c_void) -> Option<std::sync::Arc<Event>> {
    get_events()
        .lock()
        .unwrap()
        .get(&(handle as usize))
        .cloned()
}

import_fn! {
    fn CreateEventW(
        _lpEventAttributes: *mut c_void,
        bManualReset: i32,
        bInitialState: i32,
        _lpName: *const u16,
    ) -> *mut c_void {
        trace_call!("kernel32!CreateEventW");
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst) as usize;
        let event = Event {
            signalled: Mutex::new(bInitialState != 0),
            changed: std::sync::Condvar::new(),
            manual_reset: bManualReset != 0,
        };
        get_events().lock().unwrap().insert(handle, std::sync::Arc::new(event));
        handle as *mut c_void
    }

    fn SetEvent(hEvent: *mut c_void) -> i32 {
        trace_call!("kernel32!SetEvent");
        match get_event(hEvent) {
            Some(e) => {
                *e.signalled.lock().unwrap() = true;
                e.changed.notify_all();
                1
            }
            None => 0,
        }
    }

    fn ResetEvent(hEvent: *mut c_void) -> i32 {
        trace_call!("kernel32!ResetEvent");
        match get_event(hEvent) {
            Some(e) => {
                *e.signalled.lock().unwrap() = false;
                1
            }
            None => 0,
        }
    }

    // WAIT_OBJECT_0 0, WAIT_TIMEOUT 0x102, WAIT_FAILED 0xFFFFFFFF; INFINITE is 0xFFFFFFFF
    fn WaitForSingleObjectEx(hHandle: *mut c_void, dwMilliseconds: u32, _bAlertable: i32) -> u32 {
        trace_call!("kernel32!WaitForSingleObjectEx");
        let Some(e) = get_event(hHandle) else {
            return 0xFFFFFFFF;
        };
        let mut signalled = e.signalled.lock().unwrap();
        if dwMilliseconds == 0xFFFFFFFF {
            while !*signalled {
                signalled = e.changed.wait(signalled).unwrap();
            }
        } else {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(dwMilliseconds as u64);
            while !*signalled {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return 0x102;
                }
                signalled = e.changed.wait_timeout(signalled, deadline - now).unwrap().0;
            }
        }
        if !e.manual_reset {
            *signalled = false;
        }
        0
    }

    // With no name, the module the process started from, which for the DLL is d3dcompiler_47
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut c_void {
        trace_call!("kernel32!GetModuleHandleW", "name={}", if lpModuleName.is_null() {
            "<null>".to_string()
        } else {
            String::from_utf8_lossy(&wstr_to_string(lpModuleName)).trim_end_matches('\0').to_string()
        });
        if lpModuleName.is_null() {
            return super::DLL_MAP_BASE.load(Ordering::Relaxed) as *mut c_void;
        }
        module_handle(&wide_to_string(lpModuleName), false)
    }

    // An SLIST_HEADER is 16 bytes, empty when zeroed
    fn InitializeSListHead(ListHead: *mut c_void) {
        trace_call!("kernel32!InitializeSListHead");
        std::ptr::write_bytes(ListHead as *mut u8, 0, 16);
    }
}

// ============ KERNEL32 - slim locks, condition variables and one-time init ============

// An SRWLOCK and a CONDITION_VARIABLE are a pointer each, zero when unused. A lock's low 32 bits
// hold its state: the writer bit, or the count of readers. A condition variable's low 32 bits
// count wakes, which a sleeper waits to change.
const SRW_WRITER: u32 = 1 << 31;

unsafe fn futex_word(p: *mut c_void) -> &'static std::sync::atomic::AtomicU32 {
    &*(p as *const std::sync::atomic::AtomicU32)
}

unsafe fn futex_wait(word: &std::sync::atomic::AtomicU32, expected: u32, timeout_ms: u32) -> bool {
    let ts;
    let timeout = if timeout_ms == 0xFFFFFFFF {
        std::ptr::null()
    } else {
        ts = libc::timespec {
            tv_sec: (timeout_ms / 1000) as i64,
            tv_nsec: (timeout_ms % 1000) as i64 * 1_000_000,
        };
        &ts as *const libc::timespec
    };
    let r = libc::syscall(
        libc::SYS_futex,
        word.as_ptr(),
        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
        expected,
        timeout,
    );
    !(r == -1 && *libc::__errno_location() == libc::ETIMEDOUT)
}

unsafe fn futex_wake(word: &std::sync::atomic::AtomicU32, count: i32) {
    libc::syscall(
        libc::SYS_futex,
        word.as_ptr(),
        libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
        count,
    );
}

unsafe fn srw_lock_exclusive(lock: *mut c_void) {
    let word = futex_word(lock);
    loop {
        let s = word.load(Ordering::Relaxed);
        if s == 0
            && word
                .compare_exchange(0, SRW_WRITER, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
        if s != 0 {
            futex_wait(word, s, 0xFFFFFFFF);
        }
    }
}

unsafe fn srw_lock_shared(lock: *mut c_void) {
    let word = futex_word(lock);
    loop {
        let s = word.load(Ordering::Relaxed);
        if s & SRW_WRITER == 0 {
            if word
                .compare_exchange(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        } else {
            futex_wait(word, s, 0xFFFFFFFF);
        }
    }
}

unsafe fn srw_unlock_exclusive(lock: *mut c_void) {
    let word = futex_word(lock);
    word.store(0, Ordering::Release);
    futex_wake(word, i32::MAX);
}

unsafe fn srw_unlock_shared(lock: *mut c_void) {
    let word = futex_word(lock);
    if word.fetch_sub(1, Ordering::Release) == 1 {
        futex_wake(word, i32::MAX);
    }
}

import_fn! {
    fn InitializeSRWLock(SRWLock: *mut c_void) {
        trace_call!("kernel32!InitializeSRWLock");
        *(SRWLock as *mut usize) = 0;
    }

    fn AcquireSRWLockExclusive(SRWLock: *mut c_void) {
        trace_call!("kernel32!AcquireSRWLockExclusive");
        srw_lock_exclusive(SRWLock);
    }

    fn AcquireSRWLockShared(SRWLock: *mut c_void) {
        trace_call!("kernel32!AcquireSRWLockShared");
        srw_lock_shared(SRWLock);
    }

    fn TryAcquireSRWLockExclusive(SRWLock: *mut c_void) -> u8 {
        trace_call!("kernel32!TryAcquireSRWLockExclusive");
        futex_word(SRWLock).compare_exchange(0, SRW_WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() as u8
    }

    fn TryAcquireSRWLockShared(SRWLock: *mut c_void) -> u8 {
        trace_call!("kernel32!TryAcquireSRWLockShared");
        let word = futex_word(SRWLock);
        let s = word.load(Ordering::Relaxed);
        (s & SRW_WRITER == 0 && word.compare_exchange(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok()) as u8
    }

    fn ReleaseSRWLockExclusive(SRWLock: *mut c_void) {
        trace_call!("kernel32!ReleaseSRWLockExclusive");
        srw_unlock_exclusive(SRWLock);
    }

    fn ReleaseSRWLockShared(SRWLock: *mut c_void) {
        trace_call!("kernel32!ReleaseSRWLockShared");
        srw_unlock_shared(SRWLock);
    }

    fn InitializeConditionVariable(ConditionVariable: *mut c_void) {
        trace_call!("kernel32!InitializeConditionVariable");
        *(ConditionVariable as *mut usize) = 0;
    }

    // Returns 0 with ERROR_TIMEOUT when the time runs out
    fn SleepConditionVariableSRW(ConditionVariable: *mut c_void, SRWLock: *mut c_void, dwMilliseconds: u32, Flags: u32) -> i32 {
        trace_call!("kernel32!SleepConditionVariableSRW");
        let shared = Flags & 1 != 0; // CONDITION_VARIABLE_LOCKMODE_SHARED
        let cv = futex_word(ConditionVariable);
        let seq = cv.load(Ordering::Relaxed);
        if shared { srw_unlock_shared(SRWLock) } else { srw_unlock_exclusive(SRWLock) }
        let woken = futex_wait(cv, seq, dwMilliseconds);
        if shared { srw_lock_shared(SRWLock) } else { srw_lock_exclusive(SRWLock) }
        if woken {
            1
        } else {
            LAST_ERROR.store(1460, Ordering::SeqCst); // ERROR_TIMEOUT
            0
        }
    }

    fn SleepConditionVariableCS(ConditionVariable: *mut c_void, CriticalSection: *mut c_void, dwMilliseconds: u32) -> i32 {
        trace_call!("kernel32!SleepConditionVariableCS");
        let cv = futex_word(ConditionVariable);
        let seq = cv.load(Ordering::Relaxed);
        libc::pthread_mutex_unlock(CriticalSection as *mut libc::pthread_mutex_t);
        let woken = futex_wait(cv, seq, dwMilliseconds);
        libc::pthread_mutex_lock(CriticalSection as *mut libc::pthread_mutex_t);
        if woken {
            1
        } else {
            LAST_ERROR.store(1460, Ordering::SeqCst);
            0
        }
    }

    fn WakeConditionVariable(ConditionVariable: *mut c_void) {
        trace_call!("kernel32!WakeConditionVariable");
        let cv = futex_word(ConditionVariable);
        cv.fetch_add(1, Ordering::Release);
        futex_wake(cv, 1);
    }

    fn WakeAllConditionVariable(ConditionVariable: *mut c_void) {
        trace_call!("kernel32!WakeAllConditionVariable");
        let cv = futex_word(ConditionVariable);
        cv.fetch_add(1, Ordering::Release);
        futex_wake(cv, i32::MAX);
    }

    // An INIT_ONCE is a pointer: 0 before, 1 while the callback runs, 2 after. The callback's
    // context is not kept.
    fn InitOnceExecuteOnce(InitOnce: *mut c_void, InitFn: *mut c_void, Parameter: *mut c_void, Context: *mut *mut c_void) -> i32 {
        trace_call!("kernel32!InitOnceExecuteOnce");
        type Callback = unsafe extern "win64" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32;
        let state = futex_word(InitOnce);
        loop {
            match state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
                Ok(_) => {
                    let ok = std::mem::transmute::<*mut c_void, Callback>(InitFn)(InitOnce, Parameter, Context);
                    state.store(if ok != 0 { 2 } else { 0 }, Ordering::Release);
                    futex_wake(state, i32::MAX);
                    return ok;
                }
                Err(2) => return 1,
                Err(s) => {
                    futex_wait(state, s, 0xFFFFFFFF);
                }
            }
        }
    }

    fn InitializeCriticalSectionEx(lpCriticalSection: *mut c_void, _dwSpinCount: u32, _Flags: u32) -> i32 {
        trace_call!("kernel32!InitializeCriticalSectionEx");
        InitializeCriticalSection(lpCriticalSection);
        1
    }

    fn TryEnterCriticalSection(lpCriticalSection: *mut c_void) -> i32 {
        trace_call!("kernel32!TryEnterCriticalSection");
        (libc::pthread_mutex_trylock(lpCriticalSection as *mut libc::pthread_mutex_t) == 0) as i32
    }

    fn EncodePointer(Ptr: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!EncodePointer");
        Ptr
    }

    fn DecodePointer(Ptr: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!DecodePointer");
        Ptr
    }

    // STARTUPINFOW, with only its size filled in
    fn GetStartupInfoW(lpStartupInfo: *mut c_void) {
        trace_call!("kernel32!GetStartupInfoW");
        std::ptr::write_bytes(lpStartupInfo as *mut u8, 0, 104);
        *(lpStartupInfo as *mut u32) = 104;
    }

    fn GetModuleHandleExW(dwFlags: u32, lpModuleName: *const u16, phModule: *mut *mut c_void) -> i32 {
        trace_call!("kernel32!GetModuleHandleExW", "flags=0x{:x}", dwFlags);
        const FROM_ADDRESS: u32 = 4;
        let handle = if dwFlags & FROM_ADDRESS != 0 {
            crate::module::find_by_address(lpModuleName as usize).map_or(std::ptr::null_mut(), |m| m.base as *mut c_void)
        } else if lpModuleName.is_null() {
            super::DLL_MAP_BASE.load(Ordering::Relaxed) as *mut c_void
        } else {
            module_handle(&wide_to_string(lpModuleName), false)
        };
        *phModule = handle;
        if handle.is_null() {
            LAST_ERROR.store(126, Ordering::SeqCst);
        }
        (!handle.is_null()) as i32
    }

    // A loaded DLL's path, as the Linux path it was loaded from
    fn GetModuleFileNameW(hModule: *mut c_void, lpFilename: *mut u16, nSize: u32) -> u32 {
        trace_call!("kernel32!GetModuleFileNameW");
        let module = if hModule.is_null() {
            crate::module::find_by_handle(super::DLL_MAP_BASE.load(Ordering::Relaxed))
        } else {
            crate::module::find_by_handle(hModule as usize)
        };
        let Some(module) = module else {
            LAST_ERROR.store(126, Ordering::SeqCst);
            return 0;
        };
        let path = match &module.dir {
            Some(dir) => dir.join(&module.name).to_string_lossy().into_owned(),
            None => module.name.clone(),
        };
        copy_wide(&path, lpFilename, nSize)
    }

    fn GetEnvironmentVariableW(lpName: *const u16, lpBuffer: *mut u16, nSize: u32) -> u32 {
        let name = wide_to_string(lpName);
        trace_call!("kernel32!GetEnvironmentVariableW", "name={}", name);
        match std::env::var(&name) {
            Ok(value) => copy_wide(&value, lpBuffer, nSize),
            Err(_) => {
                LAST_ERROR.store(203, Ordering::SeqCst); // ERROR_ENVVAR_NOT_FOUND
                0
            }
        }
    }

    fn QueryPerformanceFrequency(lpFrequency: *mut i64) -> i32 {
        trace_call!("kernel32!QueryPerformanceFrequency");
        *lpFrequency = 1_000_000_000;
        1
    }

    fn GetTickCount64() -> u64 {
        trace_call!("kernel32!GetTickCount64");
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        (ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000) as u64
    }

    fn GetCurrentProcessorNumber() -> u32 {
        trace_call!("kernel32!GetCurrentProcessorNumber");
        libc::sched_getcpu().max(0) as u32
    }

    fn SwitchToThread() -> i32 {
        trace_call!("kernel32!SwitchToThread");
        libc::sched_yield();
        1
    }

    fn FlushProcessWriteBuffers() {
        trace_call!("kernel32!FlushProcessWriteBuffers");
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn GetNativeSystemInfo(lpSystemInfo: *mut c_void) {
        trace_call!("kernel32!GetNativeSystemInfo");
        GetSystemInfo(lpSystemInfo);
    }

    fn AreFileApisANSI() -> i32 {
        trace_call!("kernel32!AreFileApisANSI");
        1
    }

    fn SetErrorMode(_uMode: u32) -> u32 {
        trace_call!("kernel32!SetErrorMode");
        0
    }

    fn OutputDebugStringW(_lpOutputString: *const u16) {
        trace_call!("kernel32!OutputDebugStringW", "{}", wide_to_string(_lpOutputString));
    }

    fn CreateEventExW(lpEventAttributes: *mut c_void, lpName: *const u16, dwFlags: u32, _dwDesiredAccess: u32) -> *mut c_void {
        trace_call!("kernel32!CreateEventExW");
        // CREATE_EVENT_MANUAL_RESET and CREATE_EVENT_INITIAL_SET
        CreateEventW(lpEventAttributes, (dwFlags & 1 != 0) as i32, (dwFlags & 2 != 0) as i32, lpName)
    }

    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32 {
        trace_call!("kernel32!WaitForSingleObject");
        WaitForSingleObjectEx(hHandle, dwMilliseconds, 0)
    }

    // Vectored handlers only run for faults, which nothing here raises; registering one succeeds
    fn AddVectoredExceptionHandler(_First: u32, Handler: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!AddVectoredExceptionHandler");
        Handler
    }

    fn RemoveVectoredExceptionHandler(_Handle: *mut c_void) -> u32 {
        trace_call!("kernel32!RemoveVectoredExceptionHandler");
        1
    }

    fn RtlCaptureStackBackTrace(_FramesToSkip: u32, _FramesToCapture: u32, _BackTrace: *mut *mut c_void, BackTraceHash: *mut u32) -> u16 {
        trace_call!("kernel32!RtlCaptureStackBackTrace");
        if !BackTraceHash.is_null() {
            *BackTraceHash = 0;
        }
        0
    }
}

/// Writes text as a terminated UTF-16 string into a buffer of size characters, as the W functions
/// do: the length written, or the size needed, terminator included, when it does not fit
unsafe fn copy_wide(text: &str, buffer: *mut u16, size: u32) -> u32 {
    let wide: Vec<u16> = text.encode_utf16().collect();
    if wide.len() + 1 > size as usize || buffer.is_null() {
        LAST_ERROR.store(122, Ordering::SeqCst); // ERROR_INSUFFICIENT_BUFFER
        return wide.len() as u32 + 1;
    }
    std::ptr::copy_nonoverlapping(wide.as_ptr(), buffer, wide.len());
    *buffer.add(wide.len()) = 0;
    wide.len() as u32
}
