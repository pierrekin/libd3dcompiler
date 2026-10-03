//! Maps PE DLLs into the process and links them to each other and to the shims. A DLL whose
//! imports name another DLL that is loaded, or that sits beside a loaded DLL, is linked to that
//! DLL's exports; every other import goes to the shims.

use crate::linux_loader::{add_tls_template, resolve_import};
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_REL_BASED_DIR64,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::{ExportTarget, ImageOptionalHeader, Import, PeFile64};
use object::{LittleEndian as LE, Object, ObjectSection};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const UNRESOLVED: usize = 0xDEADBEEF;

enum Export {
    Address(usize),
    ForwardByName(String, String),
    ForwardByOrdinal(String, u32),
}

pub(crate) struct Module {
    /// The file name, lowercase, e.g. "msvcp140.dll"
    pub name: String,
    pub base: usize,
    pub size: usize,
    /// The address the image was linked at
    pub image_base: usize,
    /// Where the file was loaded from, searched for the DLLs it loads
    pub dir: Option<PathBuf>,
    /// The function table (.pdata), as an offset and a size
    pub exception_table: (usize, usize),
    names: HashMap<String, Export>,
    ordinals: HashMap<u32, Export>,
}

static MODULES: Mutex<Vec<&'static Module>> = Mutex::new(Vec::new());

fn normalise(name: &str) -> String {
    let name = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_lowercase();
    if name.contains('.') {
        name
    } else {
        format!("{name}.dll")
    }
}

pub(crate) fn find(name: &str) -> Option<&'static Module> {
    let name = normalise(name);
    MODULES
        .lock()
        .unwrap()
        .iter()
        .find(|m| m.name == name)
        .copied()
}

pub(crate) fn find_by_handle(handle: usize) -> Option<&'static Module> {
    MODULES
        .lock()
        .unwrap()
        .iter()
        .find(|m| m.base == handle)
        .copied()
}

/// find_by_address for a signal handler, which must not wait on the lock: None while it is held
pub(crate) fn try_find_by_address(addr: usize) -> Option<&'static Module> {
    MODULES
        .try_lock()
        .ok()?
        .iter()
        .find(|m| addr >= m.base && addr < m.base + m.size)
        .copied()
}

pub(crate) fn find_by_address(addr: usize) -> Option<&'static Module> {
    MODULES
        .lock()
        .unwrap()
        .iter()
        .find(|m| addr >= m.base && addr < m.base + m.size)
        .copied()
}

// The system's own DLLs, which the shims stand in for even when a copy sits beside a loaded DLL
const SYSTEM: &[&str] = &[
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "ucrtbase.dll",
    "msvcrt.dll",
    "advapi32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "user32.dll",
    "rpcrt4.dll",
];

pub(crate) fn is_system(name: &str) -> bool {
    let file = normalise(name);
    SYSTEM.contains(&file.as_str())
        || file.starts_with("api-ms-win-")
        || file.starts_with("ext-ms-")
}

/// A DLL that is loaded, or that can be found beside one that is
pub(crate) fn find_or_load(name: &str) -> Option<&'static Module> {
    if let Some(m) = find(name) {
        return Some(m);
    }
    let file = normalise(name);
    if is_system(&file) {
        return None;
    }
    let dirs: Vec<PathBuf> = MODULES
        .lock()
        .unwrap()
        .iter()
        .filter_map(|m| m.dir.clone())
        .collect();
    let path = dirs.iter().map(|d| d.join(&file)).find(|p| p.is_file())?;
    load_file(&path).ok()
}

/// "dll+0xoffset" for an address in a loaded DLL
pub(crate) fn describe(addr: usize) -> String {
    match find_by_address(addr) {
        Some(m) => format!("{}+0x{:x}", m.name, addr - m.base),
        None => format!("0x{addr:x}"),
    }
}

pub(crate) fn load_file(path: &Path) -> std::io::Result<&'static Module> {
    let name = normalise(&path.to_string_lossy());
    if let Some(m) = find(&name) {
        return Ok(m);
    }
    let bytes = std::fs::read(path)?;
    let dir = path.canonicalize()?.parent().map(Path::to_path_buf);
    load(&name, &bytes, dir).map_err(std::io::Error::other)
}

impl Module {
    pub(crate) fn export(&self, name: &str) -> Option<usize> {
        self.target(self.names.get(name)?)
    }

    pub(crate) fn export_by_ordinal(&self, ordinal: u32) -> Option<usize> {
        self.target(self.ordinals.get(&ordinal)?)
    }

    fn target(&self, export: &Export) -> Option<usize> {
        let addr = match export {
            Export::Address(a) => *a,
            Export::ForwardByName(dll, name) => resolve_import(dll, name).unwrap_or(UNRESOLVED),
            Export::ForwardByOrdinal(dll, ordinal) => resolve_ordinal(dll, *ordinal),
        };
        (addr != UNRESOLVED).then_some(addr)
    }
}

/// An import by ordinal, from a loaded DLL, or from the system DLLs whose ordinals the shims know
pub(crate) fn resolve_ordinal(dll: &str, ordinal: u32) -> usize {
    if let Some(m) = find_or_load(dll) {
        return m.export_by_ordinal(ordinal).unwrap_or(UNRESOLVED);
    }
    match (normalise(dll).as_str(), system_ordinal_name(dll, ordinal)) {
        (_, Some(name)) => resolve_import(dll, name).unwrap_or(UNRESOLVED),
        _ => UNRESOLVED,
    }
}

fn system_ordinal_name(dll: &str, ordinal: u32) -> Option<&'static str> {
    if normalise(dll) != "oleaut32.dll" {
        return None;
    }
    Some(match ordinal {
        2 => "SysAllocString",
        4 => "SysAllocStringLen",
        6 => "SysFreeString",
        7 => "SysStringLen",
        8 => "VariantInit",
        9 => "VariantClear",
        10 => "VariantCopy",
        12 => "VariantChangeType",
        149 => "SysStringByteLen",
        150 => "SysAllocStringByteLen",
        200 => "SetErrorInfo",
        201 => "CreateErrorInfo",
        202 => "GetErrorInfo",
        _ => return None,
    })
}

/// A stand-in for an import nothing provides: calling it names the import and aborts
fn missing_import(dll: &str, what: &str) -> usize {
    #[cfg(feature = "trace-imports")]
    eprintln!("[MISSING] {dll}!{what}");
    unsafe extern "C" fn report(name: *const std::ffi::c_char) -> ! {
        eprintln!(
            "[d3dcompiler] called an import nothing provides: {}",
            unsafe { std::ffi::CStr::from_ptr(name).to_string_lossy() }
        );
        std::process::abort();
    }
    let name = std::ffi::CString::new(format!("{dll}!{what}"))
        .unwrap()
        .into_raw() as u64;
    let mut code = vec![0x48, 0xBF];
    code.extend_from_slice(&name.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(report as *const () as u64).to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE0]);
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
        libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_EXEC);
        page as usize
    }
}

pub(crate) fn load(
    name: &str,
    dll: &[u8],
    dir: Option<PathBuf>,
) -> Result<&'static Module, String> {
    crate::fault::install();
    let pe = PeFile64::parse(dll).map_err(|e| e.to_string())?;
    let size = pe.nt_headers().optional_header.size_of_image() as usize;
    let header_size = pe.nt_headers().optional_header.size_of_headers() as usize;
    let image_base = pe.relative_address_base() as usize;

    let base = unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err("mmap failed".into());
        }
        ptr as usize
    };
    let image = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, size) };

    image[..header_size].copy_from_slice(&dll[..header_size]);
    for section in pe.sections() {
        let offset = section.address() as usize - image_base;
        if let Ok(data) = section.data() {
            let len = data.len().min(size - offset);
            image[offset..offset + len].copy_from_slice(&data[..len]);
        }
    }

    let sections = pe.section_table();
    if let Ok(Some(mut blocks)) = pe.data_directories().relocation_blocks(dll, &sections) {
        while let Ok(Some(block)) = blocks.next() {
            for reloc in block {
                let at = reloc.virtual_address as usize;
                if reloc.typ == IMAGE_REL_BASED_DIR64 && at + 8 <= size {
                    let value = u64::from_le_bytes(image[at..at + 8].try_into().unwrap());
                    let value = value - image_base as u64 + base as u64;
                    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
    }

    let mut names = HashMap::new();
    let mut ordinals = HashMap::new();
    if let Ok(Some(table)) = pe.export_table() {
        for export in table.exports().map_err(|e| e.to_string())? {
            let target = |t: ExportTarget| match t {
                ExportTarget::Address(rva) => Export::Address(base + rva as usize),
                ExportTarget::ForwardByName(dll, name) => Export::ForwardByName(
                    String::from_utf8_lossy(dll).into_owned(),
                    String::from_utf8_lossy(name).into_owned(),
                ),
                ExportTarget::ForwardByOrdinal(dll, ordinal) => {
                    Export::ForwardByOrdinal(String::from_utf8_lossy(dll).into_owned(), ordinal)
                }
            };
            if let Some(n) = export.name {
                names.insert(
                    String::from_utf8_lossy(n).into_owned(),
                    target(export.target),
                );
            }
            ordinals.insert(export.ordinal, target(export.target));
        }
    }

    let directory = |index| {
        pe.data_directories()
            .get(index)
            .map(|d| (d.virtual_address.get(LE) as usize, d.size.get(LE) as usize))
            .filter(|&(rva, _)| rva != 0)
    };
    let module: &'static Module = Box::leak(Box::new(Module {
        name: normalise(name),
        base,
        size,
        image_base,
        dir,
        exception_table: directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).unwrap_or((0, 0)),
        names,
        ordinals,
    }));
    // registered before its imports are linked, as Windows does, so DLLs that import each other
    // find it
    MODULES.lock().unwrap().push(module);

    if let Ok(Some(table)) = pe.import_table()
        && let Ok(mut descriptors) = table.descriptors()
    {
        while let Ok(Some(descriptor)) = descriptors.next() {
            let dll_name = table
                .name(descriptor.name.get(LE))
                .map(|n| String::from_utf8_lossy(n).to_lowercase())
                .unwrap_or_default();
            let Ok(mut thunks) = table.thunks(descriptor.original_first_thunk.get(LE)) else {
                continue;
            };
            let mut at = descriptor.first_thunk.get(LE) as usize;
            while let Ok(Some(thunk)) = thunks.next::<object::pe::ImageNtHeaders64>() {
                let (addr, what) = match table.import::<object::pe::ImageNtHeaders64>(thunk) {
                    Ok(Import::Name(_, name)) => {
                        let name = String::from_utf8_lossy(name).into_owned();
                        (resolve_import(&dll_name, &name).unwrap_or(UNRESOLVED), name)
                    }
                    Ok(Import::Ordinal(ordinal)) => (
                        resolve_ordinal(&dll_name, ordinal as u32),
                        format!("#{ordinal}"),
                    ),
                    Err(_) => (UNRESOLVED, "?".into()),
                };
                let addr = if addr == UNRESOLVED {
                    addr
                } else {
                    crate::fault::injected_fault(&dll_name, &what, addr).unwrap_or(addr)
                };
                let addr = if addr == UNRESOLVED {
                    missing_import(&dll_name, &what)
                } else {
                    addr
                };
                image[at..at + 8].copy_from_slice(&(addr as u64).to_le_bytes());
                at += 8;
            }
        }
    }

    for section in pe.sections() {
        let flags = match section.flags() {
            object::SectionFlags::Coff { characteristics } => characteristics,
            _ => continue,
        };
        let mut protection = 0;
        if flags & IMAGE_SCN_MEM_READ != 0 {
            protection |= libc::PROT_READ;
        }
        if flags & IMAGE_SCN_MEM_WRITE != 0 {
            protection |= libc::PROT_WRITE;
        }
        if flags & IMAGE_SCN_MEM_EXECUTE != 0 {
            protection |= libc::PROT_EXEC;
        }
        let offset = section.address() as usize - image_base;
        let len = section
            .size()
            .max(section.data().map(|d| d.len() as u64).unwrap_or(0)) as usize;
        unsafe {
            libc::mprotect((base + offset) as *mut c_void, len, protection);
        }
    }

    // Implicit TLS: each module with a TLS directory gets the next index, and every thread a copy
    // of its template. The directory's addresses are absolute and were relocated with the image.
    if let Some((rva, _)) = directory(IMAGE_DIRECTORY_ENTRY_TLS) {
        unsafe {
            let tls = (base + rva) as *const u64;
            let (start, end, index, callbacks) = (*tls, *tls.add(1), *tls.add(2), *tls.add(3));
            let zero_fill = *(tls.add(4) as *const u32) as usize;
            *(index as *mut u32) =
                add_tls_template(start as usize, (end - start) as usize, zero_fill);
            if callbacks != 0 {
                type TlsCallback = unsafe extern "win64" fn(usize, u32, *mut c_void);
                let mut cb = callbacks as *const usize;
                while *cb != 0 {
                    std::mem::transmute::<usize, TlsCallback>(*cb)(base, 1, std::ptr::null_mut());
                    cb = cb.add(1);
                }
            }
        }
    }

    let entry = pe.nt_headers().optional_header.address_of_entry_point() as usize;
    if entry != 0 {
        type DllMain = unsafe extern "win64" fn(usize, u32, *mut c_void) -> i32;
        let ok = unsafe {
            std::mem::transmute::<usize, DllMain>(base + entry)(base, 1, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(format!("{name}: DllMain failed"));
        }
    }
    Ok(module)
}

// Loads a Windows DLL, and the DLLs beside it that it imports, for a caller on Linux. Its functions
// use the Windows x64 calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_load_library(path: *const std::ffi::c_char) -> *mut c_void {
    unsafe { crate::linux_loader::setup_tib() };
    let path = unsafe { std::ffi::CStr::from_ptr(path) }
        .to_string_lossy()
        .into_owned();
    match load_file(Path::new(&path)) {
        Ok(m) => m.base as *mut c_void,
        Err(e) => {
            eprintln!("[d3dcompiler] {path}: {e}");
            std::ptr::null_mut()
        }
    }
}

// Prepares the calling thread to run code from the DLLs, which reads its Windows thread block and
// implicit TLS. Loading a DLL or looking up a function does this for the thread that does it; any
// other thread that calls into a DLL calls this first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_enter_thread() {
    unsafe { crate::linux_loader::setup_tib() };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pe_get_proc_address(
    module: *mut c_void,
    name: *const std::ffi::c_char,
) -> *mut c_void {
    unsafe { crate::linux_loader::setup_tib() };
    let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_string_lossy();
    find_by_handle(module as usize)
        .and_then(|m| m.export(&name))
        .map_or(std::ptr::null_mut(), |a| a as *mut c_void)
}
