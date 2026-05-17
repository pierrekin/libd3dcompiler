use super::*;

use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;

static EXCEPTION_FILTER: AtomicU64 = AtomicU64::new(0);
const PROCESS_HEAP: u32 = 0x12345678;
static HEAP_NEXT: AtomicU32 = AtomicU32::new(PROCESS_HEAP);
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

    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        _flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void {
        trace_call!(
            "kernel32!VirtualAlloc",
            "size={}, prot=0x{:x}",
            dwSize,
            flProtect
        );
        let prot = match flProtect {
            0x04 => libc::PROT_READ | libc::PROT_WRITE,
            0x02 => libc::PROT_READ,
            0x10 => libc::PROT_READ | libc::PROT_EXEC,
            0x20 => libc::PROT_READ | libc::PROT_EXEC,
            0x40 => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            _ => libc::PROT_READ | libc::PROT_WRITE,
        };

        let ptr = libc::mmap(
            lpAddress,
            dwSize,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );

        if ptr == libc::MAP_FAILED {
            std::ptr::null_mut()
        } else {
            virt_table()
                .lock()
                .unwrap()
                .insert(ptr as usize, dwSize);
            ptr
        }
    }

    fn VirtualFree(
        lpAddress: *mut c_void,
        dwSize: usize,
        _dwFreeType: u32,
    ) -> i32 {
        trace_call!(
            "kernel32!VirtualFree",
            "addr={:p}, size={}",
            lpAddress,
            dwSize
        );
        if lpAddress.is_null() {
            return 0;
        }
        let release_size = if dwSize == 0 {
            virt_table()
                .lock()
                .unwrap()
                .remove(&(lpAddress as usize))
                .unwrap_or(0)
        } else {
            dwSize
        };
        if release_size == 0 {
            return 1;
        }
        if libc::munmap(lpAddress, release_size) == 0 {
            1
        } else {
            0
        }
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
                libc::free(p as *mut c_void);
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
        let ptr = libc::malloc(dwBytes);
        if !ptr.is_null() {
            if dwFlags & 0x08 != 0 {
                libc::memset(ptr, 0, dwBytes);
            }
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
            if let Some(v) = t.get_mut(&(hHeap as u32)) {
                if let Some(pos) = v.iter().rposition(|&p| p == lpMem as usize) {
                    v.swap_remove(pos);
                }
            }
        }
        let new_ptr = if lpMem.is_null() {
            libc::malloc(dwBytes)
        } else {
            libc::realloc(lpMem, dwBytes)
        };
        if !new_ptr.is_null() {
            if dwFlags & 0x08 != 0 {
                libc::memset(new_ptr, 0, dwBytes);
            }
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
            if let Some(v) = t.get_mut(&(hHeap as u32)) {
                if let Some(pos) = v.iter().rposition(|&p| p == lpMem as usize) {
                    v.swap_remove(pos);
                }
            }
            libc::free(lpMem);
        }
        1
    }

    fn HeapSize(_hHeap: *mut c_void, _dwFlags: u32, _lpMem: *const c_void) -> usize {
        trace_call!("kernel32!HeapSize");
        usize::MAX
    }

    fn LocalAlloc(uFlags: u32, uBytes: usize) -> *mut c_void {
        trace_call!("kernel32!LocalAlloc", "size={}", uBytes);
        let ptr = libc::malloc(uBytes);
        if uFlags & 0x40 != 0 && !ptr.is_null() {
            libc::memset(ptr, 0, uBytes);
        }
        ptr
    }

    fn LocalFree(hMem: *mut c_void) -> *mut c_void {
        trace_call!("kernel32!LocalFree", "ptr={:p}", hMem);
        libc::free(hMem);
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
        let cs = lpCriticalSection as *mut libc::pthread_mutex_t;
        libc::pthread_mutex_init(cs, std::ptr::null());
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
        _lpLibFileName: *const u16,
        _hFile: *mut c_void,
        _dwFlags: u32,
    ) -> *mut c_void {
        trace_call!("kernel32!LoadLibraryExW");
        panic!("kernel32!LoadLibraryExW not implemented");
    }

    fn GetProcAddress(
        _hModule: *mut c_void,
        _lpProcName: *const i8,
    ) -> *mut c_void {
        trace_call!("kernel32!GetProcAddress");
        panic!("kernel32!GetProcAddress not implemented");
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
