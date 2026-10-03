use std::{collections::HashMap, sync::RwLock};

use super::*;

// ============ ADVAPI32 - registry ============

const ERROR_FILE_NOT_FOUND: i32 = 2;

struct HashContext {
    data: Vec<u8>,
    alg: u32,
}

static CRYPTO_HANDLES: OnceLock<RwLock<HashMap<usize, Box<HashContext>>>> = OnceLock::new();
static CRYPTO_NEXT: AtomicU32 = AtomicU32::new(0x2000);

fn get_crypto_handles() -> &'static RwLock<HashMap<usize, Box<HashContext>>> {
    CRYPTO_HANDLES.get_or_init(|| RwLock::new(HashMap::new()))
}

import_fn! {
    fn RegOpenKeyExA(
        _hKey: *mut c_void,
        _lpSubKey: *const i8,
        _ulOptions: u32,
        _samDesired: u32,
        _phkResult: *mut *mut c_void,
    ) -> i32 {
        trace_call!("advapi32!RegOpenKeyExA");
        ERROR_FILE_NOT_FOUND
    }

    fn RegOpenKeyExW(
        _hKey: *mut c_void,
        _lpSubKey: *const u16,
        _ulOptions: u32,
        _samDesired: u32,
        _phkResult: *mut *mut c_void,
    ) -> i32 {
        trace_call!("advapi32!RegOpenKeyExW");
        ERROR_FILE_NOT_FOUND
    }

    fn RegQueryValueExA(
        _hKey: *mut c_void,
        _lpValueName: *const i8,
        _lpReserved: *mut u32,
        _lpType: *mut u32,
        _lpData: *mut u8,
        _lpcbData: *mut u32,
    ) -> i32 {
        trace_call!("advapi32!RegQueryValueExA");
        ERROR_FILE_NOT_FOUND
    }

    fn RegQueryValueExW(
        _hKey: *mut c_void,
        _lpValueName: *const u16,
        _lpReserved: *mut u32,
        _lpType: *mut u32,
        _lpData: *mut u8,
        _lpcbData: *mut u32,
    ) -> i32 {
        trace_call!("advapi32!RegQueryValueExW");
        ERROR_FILE_NOT_FOUND
    }

    fn RegEnumKeyExA(
        _hKey: *mut c_void,
        _dwIndex: u32,
        _lpName: *mut i8,
        _lpcchName: *mut u32,
        _lpReserved: *mut u32,
        _lpClass: *mut i8,
        _lpcchClass: *mut u32,
        _lpftLastWriteTime: *mut u64,
    ) -> i32 {
        trace_call!("advapi32!RegEnumKeyExA");
        259 // ERROR_NO_MORE_ITEMS
    }

    fn RegCloseKey(_hKey: *mut c_void) -> i32 {
        trace_call!("advapi32!RegCloseKey");
        0
    }

    // ============ ADVAPI32 - crypto ============

    fn CryptAcquireContextW(
        phProv: *mut *mut c_void,
        _szContainer: *const u16,
        _szProvider: *const u16,
        _dwProvType: u32,
        _dwFlags: u32,
    ) -> i32 {
        trace_call!("advapi32!CryptAcquireContextW");
        *phProv = 0x1000 as *mut c_void;
        1
    }

    fn CryptReleaseContext(_hProv: *mut c_void, _dwFlags: u32) -> i32 {
        trace_call!("advapi32!CryptReleaseContext");
        1
    }

    fn CryptCreateHash(
        _hProv: *mut c_void,
        Algid: u32,
        _hKey: *mut c_void,
        _dwFlags: u32,
        phHash: *mut *mut c_void,
    ) -> i32 {
        trace_call!("advapi32!CryptCreateHash", "alg=0x{:x}", Algid);
        let handle = CRYPTO_NEXT.fetch_add(1, Ordering::SeqCst) as usize;
        let ctx = Box::new(HashContext {
            data: Vec::new(),
            alg: Algid,
        });
        get_crypto_handles().write().unwrap().insert(handle, ctx);
        *phHash = handle as *mut c_void;
        1
    }

    fn CryptDestroyHash(hHash: *mut c_void) -> i32 {
        trace_call!("advapi32!CryptDestroyHash");
        get_crypto_handles()
            .write()
            .unwrap()
            .remove(&(hHash as usize));
        1
    }

    fn CryptHashData(
        hHash: *mut c_void,
        pbData: *const u8,
        dwDataLen: u32,
        _dwFlags: u32,
    ) -> i32 {
        trace_call!("advapi32!CryptHashData", "len={}", dwDataLen);
        let handle = hHash as usize;
        if let Some(ctx) = get_crypto_handles().write().unwrap().get_mut(&handle) {
            let data = std::slice::from_raw_parts(pbData, dwDataLen as usize);
            ctx.data.extend_from_slice(data);
            1
        } else {
            0
        }
    }

    fn CryptGetHashParam(
        hHash: *mut c_void,
        dwParam: u32,
        pbData: *mut u8,
        pdwDataLen: *mut u32,
        _dwFlags: u32,
    ) -> i32 {
        trace_call!("advapi32!CryptGetHashParam", "param={}", dwParam);
        use sha1::{Digest, Sha1};

        let handle = hHash as usize;
        if let Some(ctx) = get_crypto_handles().read().unwrap().get(&handle) {
            if dwParam == 2 {
                // HP_HASHVAL
                let mut hasher = Sha1::new();
                hasher.update(&ctx.data);
                let result = hasher.finalize();

                if *pdwDataLen >= 20 {
                    std::ptr::copy_nonoverlapping(result.as_ptr(), pbData, 20);
                    *pdwDataLen = 20;
                    1
                } else {
                    *pdwDataLen = 20;
                    0
                }
            } else if dwParam == 4 {
                // HP_HASHSIZE
                if *pdwDataLen >= 4 {
                    *(pbData as *mut u32) = 20;
                    *pdwDataLen = 4;
                    1
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    }
}

// Event tracing: providers register and write, and nothing listens
import_fn! {
    fn EventRegister(_ProviderId: *const c_void, _EnableCallback: *mut c_void, _CallbackContext: *mut c_void, RegHandle: *mut u64) -> u32 {
        trace_call!("advapi32!EventRegister");
        *RegHandle = 1;
        0
    }

    fn EventUnregister(_RegHandle: u64) -> u32 {
        trace_call!("advapi32!EventUnregister");
        0
    }

    fn EventWriteTransfer(_RegHandle: u64, _EventDescriptor: *const c_void, _ActivityId: *const c_void, _RelatedActivityId: *const c_void, _UserDataCount: u32, _UserData: *const c_void) -> u32 {
        trace_call!("advapi32!EventWriteTransfer");
        0
    }
}
