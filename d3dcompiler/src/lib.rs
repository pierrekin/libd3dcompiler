//! Cross-platform wrapper for d3dcompiler_47.dll
//!
//! This crate provides a compatibility layer that allows using the Windows
//! D3D shader compiler on Linux by loading the DLL and implementing the
//! necessary Windows API imports.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(unsafe_op_in_unsafe_fn)]
#![recursion_limit = "256"]

mod fault;
mod imports;
mod module;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-logs")]
        eprintln!($($arg)*)
    };
}

macro_rules! debug_log_return {
    ($tag:literal, $fmt:literal, $expr:expr) => {{
        #[cfg(feature = "debug-logs")]
        {
            let result = $expr;
            eprintln!(concat!($tag, " -> ", $fmt), result);
            result
        }
        #[cfg(not(feature = "debug-logs"))]
        {
            $expr
        }
    }};
}

use d3dcompiler_proc::com_wrapper;
use std::ffi::c_void;
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum D3DCompilerError {
    #[error("Failed to load DLL: {0}")]
    LoadError(String),
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PE parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, D3DCompilerError>;

// D3D Compiler types
pub type HRESULT = i32;
pub type UINT = u32;
pub type SIZE_T = usize;
pub type LPCSTR = *const i8;
pub type LPCWSTR = *const u16;
pub type LPVOID = *mut c_void;

pub const S_OK: HRESULT = 0;
pub const E_FAIL: HRESULT = 0x80004005u32 as i32;

// D3D11 Shader Reflection descriptor types
#[repr(C)]
#[derive(Default)]
pub struct D3D11_SHADER_DESC {
    pub Version: u32,
    pub Creator: LPCSTR,
    pub Flags: u32,
    pub ConstantBuffers: u32,
    pub BoundResources: u32,
    pub InputParameters: u32,
    pub OutputParameters: u32,
    pub InstructionCount: u32,
    pub TempRegisterCount: u32,
    pub TempArrayCount: u32,
    pub DefCount: u32,
    pub DclCount: u32,
    pub TextureNormalInstructions: u32,
    pub TextureLoadInstructions: u32,
    pub TextureCompInstructions: u32,
    pub TextureBiasInstructions: u32,
    pub TextureGradientInstructions: u32,
    pub FloatInstructionCount: u32,
    pub IntInstructionCount: u32,
    pub UintInstructionCount: u32,
    pub StaticFlowControlCount: u32,
    pub DynamicFlowControlCount: u32,
    pub MacroInstructionCount: u32,
    pub ArrayInstructionCount: u32,
    pub CutInstructionCount: u32,
    pub EmitInstructionCount: u32,
    pub GSOutputTopology: u32,
    pub GSMaxOutputVertexCount: u32,
    pub InputPrimitive: u32,
    pub PatchConstantParameters: u32,
    pub cGSInstanceCount: u32,
    pub cControlPoints: u32,
    pub HSOutputPrimitive: u32,
    pub HSPartitioning: u32,
    pub TessellatorDomain: u32,
    pub cBarrierInstructions: u32,
    pub cInterlockedInstructions: u32,
    pub cTextureStoreInstructions: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct D3D11_SHADER_BUFFER_DESC {
    pub Name: LPCSTR,
    pub Type: u32,
    pub Variables: u32,
    pub Size: u32,
    pub uFlags: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct D3D11_SHADER_INPUT_BIND_DESC {
    pub Name: LPCSTR,
    pub Type: u32,
    pub BindPoint: u32,
    pub BindCount: u32,
    pub uFlags: u32,
    pub ReturnType: u32,
    pub Dimension: u32,
    pub NumSamples: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct D3D11_SIGNATURE_PARAMETER_DESC {
    pub SemanticName: LPCSTR,
    pub SemanticIndex: u32,
    pub Register: u32,
    pub SystemValueType: u32,
    pub ComponentType: u32,
    pub Mask: u8,
    pub ReadWriteMask: u8,
    pub Stream: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct D3D11_SHADER_VARIABLE_DESC {
    pub Name: LPCSTR,
    pub StartOffset: u32,
    pub Size: u32,
    pub uFlags: u32,
    pub DefaultValue: *const c_void,
    pub StartTexture: u32,
    pub TextureSize: u32,
    pub StartSampler: u32,
    pub SamplerSize: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct D3D11_SHADER_TYPE_DESC {
    pub Class: u32,
    pub Type: u32,
    pub Rows: u32,
    pub Columns: u32,
    pub Elements: u32,
    pub Members: u32,
    pub Offset: u32,
    pub Name: LPCSTR,
}

com_wrapper! {
    BlobWrapper wraps Win64Blob as ID3DBlob {
        vtable: BLOB_VTABLE: ID3DBlobVtbl,
        fn QueryInterface(riid: *const c_void, ppv: *mut *mut c_void) -> HRESULT;
        fn AddRef() -> u32;
        fn Release() -> u32 => release;
        fn GetBufferPointer() -> *mut c_void;
        fn GetBufferSize() -> SIZE_T;
    }
}

com_wrapper! {
    ReflectionWrapper wraps Win64Reflection as ID3D11ShaderReflection {
        vtable: REFLECTION_VTABLE: ID3D11ShaderReflectionVtbl,
        fn QueryInterface(riid: *const c_void, ppv: *mut *mut c_void) -> HRESULT;
        fn AddRef() -> u32;
        fn Release() -> u32 => release;
        fn GetDesc(desc: *mut D3D11_SHADER_DESC) -> HRESULT => cast;
        fn GetConstantBufferByIndex(index: UINT) -> *mut ID3D11ShaderReflectionConstantBuffer => wrap(wrap_constant_buffer);
        fn GetConstantBufferByName(name: LPCSTR) -> *mut ID3D11ShaderReflectionConstantBuffer => wrap(wrap_constant_buffer);
        fn GetResourceBindingDesc(index: UINT, desc: *mut D3D11_SHADER_INPUT_BIND_DESC) -> HRESULT => cast;
        fn GetInputParameterDesc(index: UINT, desc: *mut D3D11_SIGNATURE_PARAMETER_DESC) -> HRESULT => cast;
        fn GetOutputParameterDesc(index: UINT, desc: *mut D3D11_SIGNATURE_PARAMETER_DESC) -> HRESULT => cast;
        fn GetPatchConstantParameterDesc(index: UINT, desc: *mut D3D11_SIGNATURE_PARAMETER_DESC) -> HRESULT => cast;
        fn GetVariableByName(name: LPCSTR) -> *mut ID3D11ShaderReflectionVariable => wrap(wrap_variable);
        fn GetResourceBindingDescByName(name: LPCSTR, desc: *mut D3D11_SHADER_INPUT_BIND_DESC) -> HRESULT => cast;
        fn GetMovInstructionCount() -> UINT;
        fn GetMovcInstructionCount() -> UINT;
        fn GetConversionInstructionCount() -> UINT;
        fn GetBitwiseInstructionCount() -> UINT;
        fn GetGSInputPrimitive() -> UINT;
        fn IsSampleFrequencyShader() -> i32;
        fn GetNumInterfaceSlots() -> UINT;
        fn GetMinFeatureLevel(level: *mut UINT) -> HRESULT;
        fn GetThreadGroupSize(x: *mut UINT, y: *mut UINT, z: *mut UINT) -> UINT;
        fn GetRequiresFlags() -> u64;
    }
}

com_wrapper! {
    ConstantBufferWrapper wraps Win64ConstantBuffer as ID3D11ShaderReflectionConstantBuffer {
        vtable: CONSTANT_BUFFER_VTABLE: ID3D11ShaderReflectionConstantBufferVtbl,
        fn GetDesc(desc: *mut D3D11_SHADER_BUFFER_DESC) -> HRESULT => cast;
        fn GetVariableByIndex(index: UINT) -> *mut ID3D11ShaderReflectionVariable => wrap(wrap_variable);
        fn GetVariableByName(name: LPCSTR) -> *mut ID3D11ShaderReflectionVariable => wrap(wrap_variable);
    }
}

com_wrapper! {
    VariableWrapper wraps Win64Variable as ID3D11ShaderReflectionVariable {
        vtable: VARIABLE_VTABLE: ID3D11ShaderReflectionVariableVtbl,
        fn GetDesc(desc: *mut D3D11_SHADER_VARIABLE_DESC) -> HRESULT => cast;
        fn GetType() -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn GetBuffer() -> *mut ID3D11ShaderReflectionConstantBuffer => wrap(wrap_constant_buffer);
        fn GetInterfaceSlot(index: UINT) -> UINT;
    }
}

com_wrapper! {
    TypeWrapper wraps Win64Type as ID3D11ShaderReflectionType {
        vtable: TYPE_VTABLE: ID3D11ShaderReflectionTypeVtbl,
        fn GetDesc(desc: *mut D3D11_SHADER_TYPE_DESC) -> HRESULT => cast;
        fn GetMemberTypeByIndex(index: UINT) -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn GetMemberTypeByName(name: LPCSTR) -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn GetMemberTypeName(index: UINT) -> LPCSTR;
        fn IsEqual(other: *mut ID3D11ShaderReflectionType) -> HRESULT => unwrap(TypeWrapper, other);
        fn GetSubType() -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn GetBaseClass() -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn GetNumInterfaces() -> UINT;
        fn GetInterfaceByIndex(index: UINT) -> *mut ID3D11ShaderReflectionType => wrap(wrap_type);
        fn IsOfType(other: *mut ID3D11ShaderReflectionType) -> HRESULT => unwrap(TypeWrapper, other);
        fn ImplementsInterface(other: *mut ID3D11ShaderReflectionType) -> HRESULT => unwrap(TypeWrapper, other);
    }
}

// D3D_SHADER_MACRO
#[repr(C)]
pub struct D3D_SHADER_MACRO {
    pub Name: LPCSTR,
    pub Definition: LPCSTR,
}

// ============================================================================
// ID3DInclude wrapper (C ABI -> win64 ABI thunking)
// ============================================================================

// Internal include type expected by Windows DLL (win64 ABI)
#[repr(C)]
struct Win64Include {
    vtable: *const Win64IncludeVtbl,
}

#[repr(C)]
struct Win64IncludeVtbl {
    pub Open: unsafe extern "win64" fn(
        *mut Win64Include,
        u32,
        LPCSTR,
        *const c_void,
        *mut *const c_void,
        *mut UINT,
    ) -> HRESULT,
    pub Close: unsafe extern "win64" fn(*mut Win64Include, *const c_void) -> HRESULT,
}

// Public include type with C ABI for use with standard D3D headers
#[repr(C)]
pub struct ID3DInclude {
    pub vtable: *const ID3DIncludeVtbl,
}

#[repr(C)]
pub struct ID3DIncludeVtbl {
    pub Open: unsafe extern "C" fn(
        *mut ID3DInclude,
        u32,
        LPCSTR,
        *const c_void,
        *mut *const c_void,
        *mut UINT,
    ) -> HRESULT,
    pub Close: unsafe extern "C" fn(*mut ID3DInclude, *const c_void) -> HRESULT,
}

// Wrapper that thunks win64 ABI calls (from DLL) to C ABI calls (to user code)
#[repr(C)]
struct IncludeWrapper {
    vtable: *const Win64IncludeVtbl,
    inner: *mut ID3DInclude,
}

// Thunk: receives win64 call from DLL, forwards to user's C ABI callback
unsafe extern "win64" fn include_open_thunk(
    this: *mut Win64Include,
    include_type: u32,
    filename: LPCSTR,
    parent_data: *const c_void,
    data_out: *mut *const c_void,
    bytes_out: *mut UINT,
) -> HRESULT {
    debug_log!(
        "[INCLUDE] Open(this={:?}, type={}, filename={:?})",
        this,
        include_type,
        filename
    );
    let wrapper = this as *mut IncludeWrapper;
    let inner = (*wrapper).inner;
    debug_log_return!(
        "[INCLUDE] Open",
        "0x{:x}",
        ((*(*inner).vtable).Open)(
            inner,
            include_type,
            filename,
            parent_data,
            data_out,
            bytes_out
        )
    )
}

unsafe extern "win64" fn include_close_thunk(
    this: *mut Win64Include,
    data: *const c_void,
) -> HRESULT {
    debug_log!("[INCLUDE] Close(this={:?}, data={:?})", this, data);
    let wrapper = this as *mut IncludeWrapper;
    let inner = (*wrapper).inner;
    debug_log_return!(
        "[INCLUDE] Close",
        "0x{:x}",
        ((*(*inner).vtable).Close)(inner, data)
    )
}

// Static vtable for include wrappers
static INCLUDE_WRAPPER_VTABLE: Win64IncludeVtbl = Win64IncludeVtbl {
    Open: include_open_thunk,
    Close: include_close_thunk,
};

// Wrap a user's C ABI include in a win64 ABI wrapper for the DLL
unsafe fn wrap_include(inner: *mut ID3DInclude) -> *mut Win64Include {
    if inner.is_null() {
        return std::ptr::null_mut();
    }
    let wrapper = Box::new(IncludeWrapper {
        vtable: &INCLUDE_WRAPPER_VTABLE,
        inner,
    });
    Box::into_raw(wrapper) as *mut Win64Include
}

// Free the include wrapper (call after DLL function returns)
unsafe fn free_include_wrapper(wrapper: *mut Win64Include) {
    if !wrapper.is_null() {
        drop(Box::from_raw(wrapper as *mut IncludeWrapper));
    }
}

// Function pointer types for all exports - use win64 ABI for Windows DLL calls
// These use Win64Blob internally since they receive blobs from the Windows DLL
#[allow(non_camel_case_types)]
type PFN_D3DCompile = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut Win64Include,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    ppCode: *mut *mut Win64Blob,
    ppErrorMsgs: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DCompile2 = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut Win64Include,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    SecondaryDataFlags: UINT,
    pSecondaryData: *const c_void,
    SecondaryDataSize: SIZE_T,
    ppCode: *mut *mut Win64Blob,
    ppErrorMsgs: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DCompileFromFile = unsafe extern "win64" fn(
    pFileName: LPCWSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut Win64Include,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    ppCode: *mut *mut Win64Blob,
    ppErrorMsgs: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DPreprocess = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut Win64Include,
    ppCodeText: *mut *mut Win64Blob,
    ppErrorMsgs: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DDisassemble = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Flags: UINT,
    szComments: LPCSTR,
    ppDisassembly: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DCreateBlob =
    unsafe extern "win64" fn(Size: SIZE_T, ppBlob: *mut *mut Win64Blob) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DReflect = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pInterface: *const c_void, // REFIID
    ppReflector: *mut *mut c_void,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DStripShader = unsafe extern "win64" fn(
    pShaderBytecode: *const c_void,
    BytecodeLength: SIZE_T,
    uStripFlags: UINT,
    ppStrippedBlob: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DGetBlobPart = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Part: u32,
    Flags: UINT,
    ppPart: *mut *mut Win64Blob,
) -> HRESULT;

#[allow(non_camel_case_types)]
type PFN_D3DSetBlobPart = unsafe extern "win64" fn(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Part: u32,
    Flags: UINT,
    pPart: *const c_void,
    PartSize: SIZE_T,
    ppNewShader: *mut *mut Win64Blob,
) -> HRESULT;

// Global state for loaded DLL
struct D3DCompilerState {
    #[cfg(unix)]
    _mmap: *mut u8,
    #[cfg(unix)]
    _mmap_size: usize,

    // Function pointers
    d3d_compile: PFN_D3DCompile,
    d3d_compile2: PFN_D3DCompile2,
    d3d_compile_from_file: PFN_D3DCompileFromFile,
    d3d_preprocess: PFN_D3DPreprocess,
    d3d_disassemble: PFN_D3DDisassemble,
    d3d_create_blob: PFN_D3DCreateBlob,
    d3d_reflect: PFN_D3DReflect,
    d3d_strip_shader: PFN_D3DStripShader,
    d3d_get_blob_part: PFN_D3DGetBlobPart,
    d3d_set_blob_part: PFN_D3DSetBlobPart,
}

unsafe impl Send for D3DCompilerState {}
unsafe impl Sync for D3DCompilerState {}

static STATE: OnceLock<Result<D3DCompilerState>> = OnceLock::new();

// Expected hash for verification (update with actual hash)
static DLL_NAME: &str = "d3dcompiler_47.dll";

fn get_dll_path() -> std::path::PathBuf {
    // Look for DLL next to executable, or in current directory
    if let Ok(exe) = std::env::current_exe() {
        let path = exe.with_file_name(DLL_NAME);
        if path.exists() {
            return path;
        }
    }
    std::path::PathBuf::from(DLL_NAME)
}

// Initialize the compiler - call this before using any functions
unsafe fn init() -> &'static Result<D3DCompilerState> {
    use std::sync::Mutex;
    static INIT_ERROR: Mutex<Option<String>> = Mutex::new(None);

    unsafe { linux_loader::setup_tib() }

    STATE.get_or_init(linux_loader::load_dll)
}

// Public API functions that forward to the loaded DLL and wrap returned blobs

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DCompile(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut ID3DInclude,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    ppCode: *mut *mut ID3DBlob,
    ppErrorMsgs: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DCompile");

    // let src = slice::from_raw_parts(pSrcData.cast(), SrcDataSize);
    // let src_str = String::from_utf8_lossy(&src);

    // let name = std::ffi::CStr::from_ptr(pSourceName).to_string_lossy();
    // let entry = std::ffi::CStr::from_ptr(pEntrypoint).to_string_lossy();

    // eprintln!("COMPILING {name:?} {entry:?}");
    // let path = format!("/tmp/shaders/{}.hlsl", name.replace('/', "_"));
    // std::fs::write(&path, src).unwrap();
    // println!("{} bytes => {path}", src.len());

    let mut code: *mut Win64Blob = std::ptr::null_mut();
    let mut errors: *mut Win64Blob = std::ptr::null_mut();
    let wrapped_include = wrap_include(pInclude);
    let result = match init() {
        Ok(s) => (s.d3d_compile)(
            pSrcData,
            SrcDataSize,
            pSourceName,
            pDefines,
            wrapped_include,
            pEntrypoint,
            pTarget,
            Flags1,
            Flags2,
            &mut code,
            &mut errors,
        ),
        Err(_) => E_FAIL,
    };
    free_include_wrapper(wrapped_include);
    if !ppCode.is_null() {
        *ppCode = wrap_blob(code);
    }
    if !ppErrorMsgs.is_null() {
        *ppErrorMsgs = wrap_blob(errors);
    }
    // eprintln!("[EXPORT EXIT] D3DCompile = 0x{result:x} {ppCode:?}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DCompile2(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut ID3DInclude,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    SecondaryDataFlags: UINT,
    pSecondaryData: *const c_void,
    SecondaryDataSize: SIZE_T,
    ppCode: *mut *mut ID3DBlob,
    ppErrorMsgs: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DCompile2");
    let mut code: *mut Win64Blob = std::ptr::null_mut();
    let mut errors: *mut Win64Blob = std::ptr::null_mut();
    let wrapped_include = wrap_include(pInclude);
    let result = match init() {
        Ok(s) => (s.d3d_compile2)(
            pSrcData,
            SrcDataSize,
            pSourceName,
            pDefines,
            wrapped_include,
            pEntrypoint,
            pTarget,
            Flags1,
            Flags2,
            SecondaryDataFlags,
            pSecondaryData,
            SecondaryDataSize,
            &mut code,
            &mut errors,
        ),
        Err(_) => E_FAIL,
    };
    free_include_wrapper(wrapped_include);
    if !ppCode.is_null() {
        *ppCode = wrap_blob(code);
    }
    if !ppErrorMsgs.is_null() {
        *ppErrorMsgs = wrap_blob(errors);
    }
    // eprintln!("[EXPORT EXIT] D3DCompile2 = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DCompileFromFile(
    pFileName: LPCWSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut ID3DInclude,
    pEntrypoint: LPCSTR,
    pTarget: LPCSTR,
    Flags1: UINT,
    Flags2: UINT,
    ppCode: *mut *mut ID3DBlob,
    ppErrorMsgs: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DCompileFromFile");
    let mut code: *mut Win64Blob = std::ptr::null_mut();
    let mut errors: *mut Win64Blob = std::ptr::null_mut();
    let wrapped_include = wrap_include(pInclude);
    let result = match init() {
        Ok(s) => (s.d3d_compile_from_file)(
            pFileName,
            pDefines,
            wrapped_include,
            pEntrypoint,
            pTarget,
            Flags1,
            Flags2,
            &mut code,
            &mut errors,
        ),
        Err(_) => E_FAIL,
    };
    free_include_wrapper(wrapped_include);
    if !ppCode.is_null() {
        *ppCode = wrap_blob(code);
    }
    if !ppErrorMsgs.is_null() {
        *ppErrorMsgs = wrap_blob(errors);
    }
    // eprintln!("[EXPORT EXIT] D3DCompileFromFile = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DPreprocess(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pSourceName: LPCSTR,
    pDefines: *const D3D_SHADER_MACRO,
    pInclude: *mut ID3DInclude,
    ppCodeText: *mut *mut ID3DBlob,
    ppErrorMsgs: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DPreprocess");
    let mut code: *mut Win64Blob = std::ptr::null_mut();
    let mut errors: *mut Win64Blob = std::ptr::null_mut();
    let wrapped_include = wrap_include(pInclude);
    let result = match init() {
        Ok(s) => (s.d3d_preprocess)(
            pSrcData,
            SrcDataSize,
            pSourceName,
            pDefines,
            wrapped_include,
            &mut code,
            &mut errors,
        ),
        Err(_) => E_FAIL,
    };
    free_include_wrapper(wrapped_include);
    if !ppCodeText.is_null() {
        *ppCodeText = wrap_blob(code);
    }
    if !ppErrorMsgs.is_null() {
        *ppErrorMsgs = wrap_blob(errors);
    }
    // eprintln!("[EXPORT EXIT] D3DPreprocess = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DDisassemble(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Flags: UINT,
    szComments: LPCSTR,
    ppDisassembly: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DDisassemble");
    let mut disasm: *mut Win64Blob = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_disassemble)(pSrcData, SrcDataSize, Flags, szComments, &mut disasm),
        Err(_) => E_FAIL,
    };
    if !ppDisassembly.is_null() {
        *ppDisassembly = wrap_blob(disasm);
    }
    // eprintln!("[EXPORT EXIT] D3DDisassemble = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DCreateBlob(Size: SIZE_T, ppBlob: *mut *mut ID3DBlob) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DCreateBlob");
    let mut blob: *mut Win64Blob = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_create_blob)(Size, &mut blob),
        Err(_) => E_FAIL,
    };
    if !ppBlob.is_null() {
        *ppBlob = wrap_blob(blob);
    }
    // eprintln!("[EXPORT ENTER] D3DCreateBlob = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DReflect(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    pInterface: *const c_void,
    ppReflector: *mut *mut c_void,
) -> HRESULT {
    let mut reflector: *mut Win64Reflection = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_reflect)(
            pSrcData,
            SrcDataSize,
            pInterface,
            &mut reflector as *mut _ as *mut *mut c_void,
        ),
        Err(_) => E_FAIL,
    };
    if !ppReflector.is_null() {
        *ppReflector = wrap_reflection(reflector) as *mut c_void;
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DStripShader(
    pShaderBytecode: *const c_void,
    BytecodeLength: SIZE_T,
    uStripFlags: UINT,
    ppStrippedBlob: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DStripShader");
    let mut blob: *mut Win64Blob = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_strip_shader)(pShaderBytecode, BytecodeLength, uStripFlags, &mut blob),
        Err(_) => E_FAIL,
    };
    if !ppStrippedBlob.is_null() {
        *ppStrippedBlob = wrap_blob(blob);
    }
    // eprintln!("[EXPORT EXIT] D3DStripShader = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DGetBlobPart(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Part: u32,
    Flags: UINT,
    ppPart: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DGetBlobPart");
    let mut blob: *mut Win64Blob = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_get_blob_part)(pSrcData, SrcDataSize, Part, Flags, &mut blob),
        Err(_) => E_FAIL,
    };
    if !ppPart.is_null() {
        *ppPart = wrap_blob(blob);
    }
    // eprintln!("[EXPORT EXIT] D3DGetBlobPart = 0x{result:x}");
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn D3DSetBlobPart(
    pSrcData: *const c_void,
    SrcDataSize: SIZE_T,
    Part: u32,
    Flags: UINT,
    pPart: *const c_void,
    PartSize: SIZE_T,
    ppNewShader: *mut *mut ID3DBlob,
) -> HRESULT {
    // eprintln!("[EXPORT ENTER] D3DSetBlobPart");
    let mut blob: *mut Win64Blob = std::ptr::null_mut();
    let result = match init() {
        Ok(s) => (s.d3d_set_blob_part)(
            pSrcData,
            SrcDataSize,
            Part,
            Flags,
            pPart,
            PartSize,
            &mut blob,
        ),
        Err(_) => E_FAIL,
    };
    if !ppNewShader.is_null() {
        *ppNewShader = wrap_blob(blob);
    }
    // eprintln!("[EXPORT EXIT] D3DSetBlobPart = 0x{result:x}");
    result
}

// Linux loader - manual PE loading with import hooking
#[cfg(unix)]
mod linux_loader {
    use super::*;

    // Thread Information Block for Windows ABI compatibility
    // Windows x64 TEB layout (relevant fields):
    //   0x00: ExceptionList (NT_TIB.ExceptionList)
    //   0x08: StackBase (NT_TIB.StackBase)
    //   0x10: StackLimit (NT_TIB.StackLimit)
    //   0x18: SubSystemTib
    //   0x20: FiberData / Version
    //   0x28: ArbitraryUserPointer
    //   0x30: Self (pointer to TEB itself - NT_TIB.Self)
    //   0x58: ThreadLocalStoragePointer (array of each module's implicit TLS block)
    //   0x60: ProcessEnvironmentBlock
    #[repr(C)]
    struct ThreadInformationBlock {
        exception_list: usize,         // 0x00
        stack_base: usize,             // 0x08
        stack_limit: usize,            // 0x10
        sub_system_tib: usize,         // 0x18
        fiber_data: usize,             // 0x20
        arbitrary_user_pointer: usize, // 0x28
        teb_self: usize,               // 0x30 - MUST point to this struct itself!
        environment_pointer: usize,    // 0x38
        process_id: usize,             // 0x40
        thread_id: usize,              // 0x48
        active_rpc_handle: usize,      // 0x50
        tls_pointer: usize,            // 0x58
        peb: usize,                    // 0x60
    }

    // Thread-local TIB - each thread gets its own
    thread_local! {
        static TIB: std::cell::UnsafeCell<ThreadInformationBlock> = const {
            std::cell::UnsafeCell::new(ThreadInformationBlock {
                exception_list: 0,
                stack_base: 0,
                stack_limit: 0,
                sub_system_tib: 0,
                fiber_data: 0,
                arbitrary_user_pointer: 0,
                teb_self: 0,
                environment_pointer: 0,
                process_id: 0,
                thread_id: 0,
                active_rpc_handle: 0,
                tls_pointer: 0,
                peb: 0,
            })
        };
        static TIB_INITIALIZED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    // Each module's implicit TLS template (__declspec(thread) variables, and the epoch MSVC's
    // guarded statics compare against), by TLS index: its address in the mapped image, its
    // initialised size and the zeros after it. Each thread gets its own copy of each, in the TLS
    // array at TEB+0x58.
    static TLS_TEMPLATES: std::sync::Mutex<Vec<(usize, usize, usize)>> =
        std::sync::Mutex::new(Vec::new());
    const TLS_SLOTS: usize = 64;

    /// Registers a module's TLS template, gives this thread its copy, and returns its index
    pub(crate) fn add_tls_template(start: usize, len: usize, zero_fill: usize) -> u32 {
        let index = {
            let mut templates = TLS_TEMPLATES.lock().unwrap();
            assert!(templates.len() < TLS_SLOTS, "too many modules with TLS");
            templates.push((start, len, zero_fill));
            templates.len() - 1
        };
        unsafe { setup_thread_tls() };
        index as u32
    }

    unsafe fn setup_thread_tls() {
        let templates = TLS_TEMPLATES.lock().unwrap();
        if templates.is_empty() {
            return;
        }
        TIB.with(|tib| {
            let tib_ptr = tib.get();
            if (*tib_ptr).tls_pointer == 0 {
                (*tib_ptr).tls_pointer =
                    libc::calloc(TLS_SLOTS, std::mem::size_of::<usize>()) as usize;
            }
            let slots = (*tib_ptr).tls_pointer as *mut usize;
            for (i, &(start, len, zero_fill)) in templates.iter().enumerate() {
                if *slots.add(i) == 0 {
                    let block = libc::calloc(1, (len + zero_fill).max(1)) as *mut u8;
                    std::ptr::copy_nonoverlapping(start as *const u8, block, len);
                    *slots.add(i) = block as usize;
                }
            }
        });
    }

    // Set up GS register for Windows TIB access (once per thread)
    pub unsafe fn setup_tib() {
        setup_thread_tls();
        TIB_INITIALIZED.with(|initialized| {
            if initialized.get() {
                return;
            }

            TIB.with(|tib| {
                let tib_ptr = tib.get();

                // Get current stack info
                let mut stack_var: usize = 0;
                let stack_ptr = (&raw mut stack_var) as usize;

                // Estimate stack bounds (stack grows down on x86-64)
                // Use 8MB stack size estimate for maximum compatibility
                let stack_base = (stack_ptr + 0x800000) & !0xFFF;
                let stack_limit = (stack_ptr - 0x800000) & !0xFFF;

                // Initialize TIB fields
                (*tib_ptr).stack_base = stack_base;
                (*tib_ptr).stack_limit = stack_limit;
                (*tib_ptr).teb_self = tib_ptr as usize;
                (*tib_ptr).process_id = std::process::id() as usize;
                (*tib_ptr).thread_id = libc::syscall(libc::SYS_gettid) as usize;

                // Set GS base to point to our TIB using arch_prctl
                const ARCH_SET_GS: i32 = 0x1001;
                libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, tib_ptr as usize);
            });

            initialized.set(true);
        });
    }

    // // Global state for crash debugging
    // static mut DLL_MAP_BASE: usize = 0;
    // static mut DLL_MAP_SIZE: usize = 0;
    // static mut DLL_IMAGE_BASE: usize = 0;

    // unsafe extern "C" fn crash_handler(
    //     sig: i32,
    //     _info: *mut libc::siginfo_t,
    //     context: *mut c_void,
    // ) {
    //     let uc = context as *mut libc::ucontext_t;
    //     let rip = (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
    //     let rsp = (*uc).uc_mcontext.gregs[libc::REG_RSP as usize] as u64;
    //     let rax = (*uc).uc_mcontext.gregs[libc::REG_RAX as usize] as u64;
    //     let rbx = (*uc).uc_mcontext.gregs[libc::REG_RBX as usize] as u64;
    //     let rcx = (*uc).uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
    //     let rdx = (*uc).uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
    //     let rsi = (*uc).uc_mcontext.gregs[libc::REG_RSI as usize] as u64;
    //     let rdi = (*uc).uc_mcontext.gregs[libc::REG_RDI as usize] as u64;
    //     let r8 = (*uc).uc_mcontext.gregs[libc::REG_R8 as usize] as u64;
    //     let r9 = (*uc).uc_mcontext.gregs[libc::REG_R9 as usize] as u64;

    //     eprintln!("\n============================================================");
    //     eprintln!("CRASH: Signal {} at RIP=0x{:016x}", sig, rip);
    //     eprintln!("============================================================");

    //     // Check if crash is in DLL
    //     let map_base = DLL_MAP_BASE;
    //     let map_size = DLL_MAP_SIZE;
    //     let image_base = DLL_IMAGE_BASE;

    //     if map_base != 0 && (rip as usize) >= map_base && (rip as usize) < map_base + map_size {
    //         let dll_offset = rip as usize - map_base;
    //         let dll_rva = dll_offset; // RVA from start of image
    //         let original_va = image_base + dll_offset; // VA in original DLL

    //         eprintln!("CRASH IN DLL:");
    //         eprintln!("  Map base:        0x{:016x}", map_base);
    //         eprintln!("  Crash RIP:       0x{:016x}", rip);
    //         eprintln!("  DLL offset/RVA:  0x{:08x}", dll_rva);
    //         eprintln!("  Original VA:     0x{:016x}", original_va);
    //         eprintln!("");
    //         eprintln!("To debug in IDA/Ghidra, go to address: 0x{:x}", original_va);
    //         eprintln!(
    //             "Or use RVA: 0x{:x} from image base 0x{:x}",
    //             dll_rva, image_base
    //         );
    //     } else {
    //         eprintln!(
    //             "Crash outside DLL (map_base=0x{:x}, size=0x{:x})",
    //             map_base, map_size
    //         );
    //     }

    //     eprintln!("\nRegisters:");
    //     eprintln!("  RAX=0x{:016x}  RBX=0x{:016x}", rax, rbx);
    //     eprintln!("  RCX=0x{:016x}  RDX=0x{:016x}", rcx, rdx);
    //     eprintln!("  RSI=0x{:016x}  RDI=0x{:016x}", rsi, rdi);
    //     eprintln!("  R8 =0x{:016x}  R9 =0x{:016x}", r8, r9);
    //     eprintln!("  RSP=0x{:016x}  RIP=0x{:016x}", rsp, rip);

    //     // Dump stack
    //     eprintln!("\nStack (top 16 qwords):");
    //     let stack = rsp as *const u64;
    //     for i in 0..16 {
    //         let addr = stack.add(i);
    //         let val = *addr;
    //         let in_dll = (val as usize) >= map_base && (val as usize) < map_base + map_size;
    //         if in_dll {
    //             let rva = val as usize - map_base;
    //             eprintln!(
    //                 "  [RSP+0x{:02x}] 0x{:016x}  <- DLL RVA 0x{:x}",
    //                 i * 8,
    //                 val,
    //                 rva
    //             );
    //         } else {
    //             eprintln!("  [RSP+0x{:02x}] 0x{:016x}", i * 8, val);
    //         }
    //     }

    //     // Dump bytes at RIP
    //     eprintln!("\nCode at RIP:");
    //     let code = rip as *const u8;
    //     eprint!("  ");
    //     for i in 0..32 {
    //         eprint!("{:02x} ", *code.add(i));
    //     }
    //     eprintln!();

    //     eprintln!("============================================================\n");

    //     std::process::abort();
    // }

    // pub fn install_crash_handler() {
    //     unsafe {
    //         let mut sa: libc::sigaction = std::mem::zeroed();
    //         sa.sa_sigaction = crash_handler as usize;
    //         sa.sa_flags = libc::SA_SIGINFO;
    //         libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
    //         libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
    //         libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut());
    //     }
    // }

    #[cfg(feature = "embed-dll")]
    static EMBEDDED_DLL: &[u8] =
        include_bytes_aligned::include_bytes_aligned!(8, "../../d3dcompiler_47.dll");

    pub fn load_dll() -> Result<D3DCompilerState> {
        #[cfg(feature = "embed-dll")]
        let dll: &[u8] = EMBEDDED_DLL;

        #[cfg(not(feature = "embed-dll"))]
        let dll_vec = std::fs::read(get_dll_path())?;
        #[cfg(not(feature = "embed-dll"))]
        let dll: &[u8] = &dll_vec;

        let module =
            crate::module::load(DLL_NAME, dll, None).map_err(D3DCompilerError::LoadError)?;

        // Store globals for import tracing
        imports::DLL_MAP_BASE.store(module.base, std::sync::atomic::Ordering::Relaxed);
        imports::DLL_MAP_SIZE.store(module.size, std::sync::atomic::Ordering::Relaxed);
        imports::DLL_IMAGE_BASE.store(module.image_base, std::sync::atomic::Ordering::Relaxed);

        let get_fn = |name: &str| -> Result<*const c_void> {
            module
                .export(name)
                .map(|a| a as *const c_void)
                .ok_or_else(|| D3DCompilerError::FunctionNotFound(name.into()))
        };

        unsafe {
            let state = D3DCompilerState {
                _mmap: module.base as *mut u8,
                _mmap_size: module.size,
                d3d_compile: std::mem::transmute(get_fn("D3DCompile")?),
                d3d_compile2: std::mem::transmute(get_fn("D3DCompile2")?),
                d3d_compile_from_file: std::mem::transmute(get_fn("D3DCompileFromFile")?),
                d3d_preprocess: std::mem::transmute(get_fn("D3DPreprocess")?),
                d3d_disassemble: std::mem::transmute(get_fn("D3DDisassemble")?),
                d3d_create_blob: std::mem::transmute(get_fn("D3DCreateBlob")?),
                d3d_reflect: std::mem::transmute(get_fn("D3DReflect")?),
                d3d_strip_shader: std::mem::transmute(get_fn("D3DStripShader")?),
                d3d_get_blob_part: std::mem::transmute(get_fn("D3DGetBlobPart")?),
                d3d_set_blob_part: std::mem::transmute(get_fn("D3DSetBlobPart")?),
            };
            Ok(state)
        }
    }

    // Import resolver - resolves by DLL name and import name, None if no shim exists
    pub(crate) fn resolve_import(dll: &str, name: &str) -> Option<usize> {
        if let Some(module) = crate::module::find_or_load(dll) {
            return module.export(name);
        }
        let dll = dll.to_lowercase();
        // Normalize DLL name (remove .dll extension if present)
        let dll_base = dll.trim_end_matches(".dll");
        let mut addr = resolve_import_exact(dll_base, name);
        // The Universal CRT's private exports, which Microsoft's own DLLs import, are the C runtime's
        // functions with an _o_ prefix
        if addr == 0
            && let Some(plain) = name.strip_prefix("_o_")
        {
            addr = resolve_import_exact(dll_base, plain);
        }
        // kernel32 forwards the Rtl* functions to ntdll
        if addr == 0 && (dll_base == "kernel32" || dll_base.starts_with("api-ms-win-core-")) {
            addr = resolve_ntdll(name);
        }
        (addr != 0).then_some(addr)
    }

    // Per-DLL resolvers return 0 for unknown names
    fn resolve_import_exact(dll_base: &str, name: &str) -> usize {
        match dll_base {
            "msvcrt"
            | "msvcr100"
            | "msvcr110"
            | "msvcr120"
            | "vcruntime140"
            | "ucrtbase"
            | "api-ms-win-crt-runtime-l1-1-0"
            | "api-ms-win-crt-heap-l1-1-0"
            | "api-ms-win-crt-string-l1-1-0"
            | "api-ms-win-crt-stdio-l1-1-0"
            | "api-ms-win-crt-math-l1-1-0"
            | "api-ms-win-crt-convert-l1-1-0"
            | "api-ms-win-crt-utility-l1-1-0"
            | "api-ms-win-crt-time-l1-1-0"
            | "api-ms-win-crt-locale-l1-1-0"
            | "api-ms-win-crt-environment-l1-1-0"
            | "api-ms-win-crt-filesystem-l1-1-0"
            | "api-ms-win-crt-private-l1-1-0" => resolve_msvcrt(name),
            "kernel32"
            | "api-ms-win-core-heap-l1-1-0"
            | "api-ms-win-core-synch-l1-1-0"
            | "api-ms-win-core-synch-l1-2-0"
            | "api-ms-win-core-file-l1-1-0"
            | "api-ms-win-core-file-l1-2-0"
            | "api-ms-win-core-file-l2-1-0"
            | "api-ms-win-core-processthreads-l1-1-0"
            | "api-ms-win-core-processthreads-l1-1-1"
            | "api-ms-win-core-libraryloader-l1-1-0"
            | "api-ms-win-core-libraryloader-l1-2-0"
            | "api-ms-win-core-memory-l1-1-0"
            | "api-ms-win-core-localization-l1-2-0"
            | "api-ms-win-core-sysinfo-l1-1-0"
            | "api-ms-win-core-errorhandling-l1-1-0"
            | "api-ms-win-core-profile-l1-1-0"
            | "api-ms-win-core-string-l1-1-0"
            | "api-ms-win-core-debug-l1-1-0"
            | "api-ms-win-core-handle-l1-1-0"
            | "api-ms-win-core-fibers-l1-1-0"
            | "api-ms-win-core-fibers-l1-1-1" => resolve_kernel32(name),
            "advapi32" | "api-ms-win-core-registry-l1-1-0" | "api-ms-win-security-base-l1-1-0" => {
                resolve_advapi32(name)
            }
            "ntdll" => resolve_ntdll(name),
            "ole32" | "oleaut32" => resolve_ole32(name),
            "rpcrt4" => resolve_rpcrt4(name),
            _ => 0,
        }
    }

    fn resolve_msvcrt(name: &str) -> usize {
        match name {
            // memory
            "malloc" => imports::msvcrt::malloc as *const () as usize,
            "free" => imports::msvcrt::free as *const () as usize,
            "??2@YAPEAX_K@Z" => imports::msvcrt::op_new as *const () as usize,
            "??3@YAXPEAX@Z" => imports::msvcrt::op_delete as *const () as usize,
            "??_U@YAPEAX_K@Z" => imports::msvcrt::op_new_array as *const () as usize,
            "??_V@YAXPEAX@Z" => imports::msvcrt::op_delete_array as *const () as usize,
            "memcpy" => imports::msvcrt::memcpy as *const () as usize,
            "memcpy_s" => imports::msvcrt::memcpy_s as *const () as usize,
            "memmove" => imports::msvcrt::memmove as *const () as usize,
            "memset" => imports::msvcrt::memset as *const () as usize,
            "memcmp" => imports::msvcrt::memcmp as *const () as usize,
            "_memicmp" => imports::msvcrt::_memicmp as *const () as usize,

            // string
            "strlen" => imports::msvcrt::strlen as *const () as usize,
            "strcmp" => imports::msvcrt::strcmp as *const () as usize,
            "strncmp" => imports::msvcrt::strncmp as *const () as usize,
            "strcpy_s" => imports::msvcrt::strcpy_s as *const () as usize,
            "strncpy_s" => imports::msvcrt::strncpy_s as *const () as usize,
            "strcat_s" => imports::msvcrt::strcat_s as *const () as usize,
            "strchr" => imports::msvcrt::strchr as *const () as usize,
            "strrchr" => imports::msvcrt::strrchr as *const () as usize,
            "strstr" => imports::msvcrt::strstr as *const () as usize,
            "strnlen" => imports::msvcrt::strnlen as *const () as usize,
            "_strdup" => imports::msvcrt::_strdup as *const () as usize,
            "_stricmp" => imports::msvcrt::_stricmp as *const () as usize,
            "_strnicmp" => imports::msvcrt::_strnicmp as *const () as usize,
            "tolower" => imports::msvcrt::tolower as *const () as usize,
            "toupper" => imports::msvcrt::toupper as *const () as usize,
            "towlower" => imports::msvcrt::towlower as *const () as usize,
            "isalnum" => imports::msvcrt::isalnum as *const () as usize,
            "isalpha" => imports::msvcrt::isalpha as *const () as usize,
            "isdigit" => imports::msvcrt::isdigit as *const () as usize,
            "iswdigit" => imports::msvcrt::iswdigit as *const () as usize,
            "isspace" => imports::msvcrt::isspace as *const () as usize,
            "isxdigit" => imports::msvcrt::isxdigit as *const () as usize,
            "__isascii" => imports::msvcrt::__isascii as *const () as usize,

            // wide string
            "wcsncmp" => imports::msvcrt::wcsncmp as *const () as usize,
            "wcsncpy_s" => imports::msvcrt::wcsncpy_s as *const () as usize,
            "wcsncat_s" => imports::msvcrt::wcsncat_s as *const () as usize,
            "wcscat_s" => imports::msvcrt::wcscat_s as *const () as usize,
            "wcscpy_s" => imports::msvcrt::wcscpy_s as *const () as usize,
            "wcschr" => imports::msvcrt::wcschr as *const () as usize,
            "wcsrchr" => imports::msvcrt::wcsrchr as *const () as usize,
            "_wcsdup" => imports::msvcrt::_wcsdup as *const () as usize,
            "_wcsicmp" => imports::msvcrt::_wcsicmp as *const () as usize,
            "_wcsnicmp" => imports::msvcrt::_wcsnicmp as *const () as usize,
            "_mbscmp" => imports::msvcrt::_mbscmp as *const () as usize,
            "_mbstrlen" => imports::msvcrt::_mbstrlen as *const () as usize,

            // printf/scanf
            "sprintf_s" => imports::msvcrt::sprintf_s as *const () as usize,
            "sscanf" => imports::msvcrt::sscanf as *const () as usize,
            "vsprintf_s" => imports::msvcrt::vsprintf_s as *const () as usize,
            "sscanf_s" => imports::msvcrt::sscanf_s as *const () as usize,
            "swprintf_s" => imports::msvcrt::swprintf_s as *const () as usize,
            "_vsnprintf" => imports::msvcrt::_vsnprintf as *const () as usize,
            "_vsnwprintf" => imports::msvcrt::_vsnwprintf as *const () as usize,
            "_snwprintf_s" => imports::msvcrt::_snwprintf_s as *const () as usize,

            // file I/O
            "fclose" => imports::msvcrt::fclose as *const () as usize,
            "fread" => imports::msvcrt::fread as *const () as usize,
            "fseek" => imports::msvcrt::fseek as *const () as usize,
            "ftell" => imports::msvcrt::ftell as *const () as usize,
            "_wfsopen" => imports::msvcrt::_wfsopen as *const () as usize,
            "_fileno" => imports::msvcrt::_fileno as *const () as usize,
            "_filelengthi64" => imports::msvcrt::_filelengthi64 as *const () as usize,
            "_read" => imports::msvcrt::_read as *const () as usize,
            "_write" => imports::msvcrt::_write as *const () as usize,
            "_close" => imports::msvcrt::_close as *const () as usize,
            "_lseeki64" => imports::msvcrt::_lseeki64 as *const () as usize,
            "_chsize_s" => imports::msvcrt::_chsize_s as *const () as usize,
            "_chsize" => imports::msvcrt::_chsize as *const () as usize,
            "_wsopen" => imports::msvcrt::_wsopen as *const () as usize,
            "_get_osfhandle" => imports::msvcrt::_get_osfhandle as *const () as usize,
            "_open_osfhandle" => imports::msvcrt::_open_osfhandle as *const () as usize,

            // math
            "acos" => imports::msvcrt::acos as *const () as usize,
            "asin" => imports::msvcrt::asin as *const () as usize,
            "atan" => imports::msvcrt::atan as *const () as usize,
            "atan2" => imports::msvcrt::atan2 as *const () as usize,
            "ceil" => imports::msvcrt::ceil as *const () as usize,
            "cos" => imports::msvcrt::cos as *const () as usize,
            "cosh" => imports::msvcrt::cosh as *const () as usize,
            "exp" => imports::msvcrt::exp as *const () as usize,
            "floor" => imports::msvcrt::floor as *const () as usize,
            "floorf" => imports::msvcrt::floorf as *const () as usize,
            "fmod" => imports::msvcrt::fmod as *const () as usize,
            "log" => imports::msvcrt::log as *const () as usize,
            "modf" => imports::msvcrt::modf as *const () as usize,
            "pow" => imports::msvcrt::pow as *const () as usize,
            "sin" => imports::msvcrt::sin as *const () as usize,
            "sinh" => imports::msvcrt::sinh as *const () as usize,
            "sqrt" => imports::msvcrt::sqrt as *const () as usize,
            "tan" => imports::msvcrt::tan as *const () as usize,
            "tanh" => imports::msvcrt::tanh as *const () as usize,
            "_isnan" => imports::msvcrt::_isnan as *const () as usize,
            "_finite" => imports::msvcrt::_finite as *const () as usize,
            "_fpclass" => imports::msvcrt::_fpclass as *const () as usize,
            "_clearfp" => imports::msvcrt::_clearfp as *const () as usize,
            "_controlfp" => imports::msvcrt::_controlfp as *const () as usize,

            // conversion
            "atoi" => imports::msvcrt::atoi as *const () as usize,
            "atof" => imports::msvcrt::atof as *const () as usize,
            "_atoi64" => imports::msvcrt::_atoi64 as *const () as usize,
            "strtod" => imports::msvcrt::strtod as *const () as usize,
            "strtoul" => imports::msvcrt::strtoul as *const () as usize,
            "wcstoul" => imports::msvcrt::wcstoul as *const () as usize,
            "wcstol" => imports::msvcrt::wcstol as *const () as usize,
            "_strtoui64" => imports::msvcrt::_strtoui64 as *const () as usize,

            // other
            "qsort" => imports::msvcrt::qsort as *const () as usize,
            "bsearch" => imports::msvcrt::bsearch as *const () as usize,
            "getenv" => imports::msvcrt::getenv as *const () as usize,
            "_wgetenv" => imports::msvcrt::_wgetenv as *const () as usize,
            "setlocale" => imports::msvcrt::setlocale as *const () as usize,
            "_time64" => imports::msvcrt::_time64 as *const () as usize,
            "_errno" => imports::msvcrt::_errno as *const () as usize,

            // CRT init
            "_initterm" => imports::msvcrt::_initterm as *const () as usize,
            "calloc" => imports::msvcrt::calloc as *const () as usize,
            "_configure_narrow_argv" => {
                imports::msvcrt::_configure_narrow_argv as *const () as usize
            }
            "_initialize_narrow_environment" => {
                imports::msvcrt::_initialize_narrow_environment as *const () as usize
            }
            "_initialize_onexit_table" => {
                imports::msvcrt::_initialize_onexit_table as *const () as usize
            }
            "_register_onexit_function" => {
                imports::msvcrt::_register_onexit_function as *const () as usize
            }
            "_execute_onexit_table" => imports::msvcrt::_execute_onexit_table as *const () as usize,
            "_crt_atexit" => imports::msvcrt::_crt_atexit as *const () as usize,
            "_cexit" => imports::msvcrt::_cexit as *const () as usize,
            "__std_type_info_destroy_list" => {
                imports::msvcrt::__std_type_info_destroy_list as *const () as usize
            }
            "_seh_filter_dll" => imports::msvcrt::_seh_filter_dll as *const () as usize,
            "_invalid_parameter_noinfo" => {
                imports::msvcrt::_invalid_parameter_noinfo as *const () as usize
            }
            "terminate" => imports::msvcrt::terminate as *const () as usize,
            "_wtoi" => imports::msvcrt::_wtoi as *const () as usize,
            "_wsopen_s" => imports::msvcrt::_wsopen_s as *const () as usize,
            "__stdio_common_vsprintf" => {
                imports::msvcrt::__stdio_common_vsprintf as *const () as usize
            }
            "__stdio_common_vsprintf_s" => {
                imports::msvcrt::__stdio_common_vsprintf_s as *const () as usize
            }
            "__stdio_common_vsnprintf_s" => {
                imports::msvcrt::__stdio_common_vsnprintf_s as *const () as usize
            }
            "__stdio_common_vswprintf" => {
                imports::msvcrt::__stdio_common_vswprintf as *const () as usize
            }
            "__stdio_common_vswprintf_s" => {
                imports::msvcrt::__stdio_common_vswprintf_s as *const () as usize
            }
            "__stdio_common_vsnwprintf_s" => {
                imports::msvcrt::__stdio_common_vsnwprintf_s as *const () as usize
            }
            "__stdio_common_vsscanf" => {
                imports::msvcrt::__stdio_common_vsscanf as *const () as usize
            }
            "_initterm_e" => imports::msvcrt::_initterm_e as *const () as usize,
            "_amsg_exit" => imports::msvcrt::_amsg_exit as *const () as usize,
            "_purecall" => imports::msvcrt::_purecall as *const () as usize,
            "_onexit" => imports::msvcrt::_onexit as *const () as usize,
            "__dllonexit" => imports::msvcrt::__dllonexit as *const () as usize,
            "_lock" => imports::msvcrt::_lock as *const () as usize,
            "_unlock" => imports::msvcrt::_unlock as *const () as usize,
            "_callnewh" => imports::msvcrt::_callnewh as *const () as usize,

            // exceptions
            "__C_specific_handler" => imports::msvcrt::__C_specific_handler as *const () as usize,
            "__CxxFrameHandler3" => imports::msvcrt::__CxxFrameHandler3 as *const () as usize,
            "_CxxThrowException" => imports::msvcrt::_CxxThrowException as *const () as usize,
            "?terminate@@YAXXZ" => imports::msvcrt::terminate as *const () as usize,
            "??1type_info@@UEAA@XZ" => imports::msvcrt::type_info_dtor as *const () as usize,
            "__unDName" => imports::msvcrt::__unDName as *const () as usize,
            "_XcptFilter" => imports::msvcrt::_XcptFilter as *const () as usize,

            // path
            "_wfullpath" => imports::msvcrt::_wfullpath as *const () as usize,
            "_wmakepath_s" => imports::msvcrt::_wmakepath_s as *const () as usize,
            "_wsplitpath_s" => imports::msvcrt::_wsplitpath_s as *const () as usize,
            "acosf" => imports::msvcrt::acosf as *const () as usize,
            "asinf" => imports::msvcrt::asinf as *const () as usize,
            "atanf" => imports::msvcrt::atanf as *const () as usize,
            "atan2f" => imports::msvcrt::atan2f as *const () as usize,
            "ceilf" => imports::msvcrt::ceilf as *const () as usize,
            "copysign" => imports::msvcrt::copysign as *const () as usize,
            "cosf" => imports::msvcrt::cosf as *const () as usize,
            "coshf" => imports::msvcrt::coshf as *const () as usize,
            "exp2" => imports::msvcrt::exp2 as *const () as usize,
            "exp2f" => imports::msvcrt::exp2f as *const () as usize,
            "expf" => imports::msvcrt::expf as *const () as usize,
            "fabs" => imports::msvcrt::fabs as *const () as usize,
            "frexp" => imports::msvcrt::frexp_ as *const () as usize,
            "ldexp" => imports::msvcrt::ldexp_ as *const () as usize,
            "log10" => imports::msvcrt::log10 as *const () as usize,
            "log10f" => imports::msvcrt::log10f as *const () as usize,
            "log2" => imports::msvcrt::log2 as *const () as usize,
            "log2f" => imports::msvcrt::log2f as *const () as usize,
            "logf" => imports::msvcrt::logf as *const () as usize,
            "nearbyint" => imports::msvcrt::nearbyint as *const () as usize,
            "nearbyintf" => imports::msvcrt::nearbyintf as *const () as usize,
            "powf" => imports::msvcrt::powf as *const () as usize,
            "round" => imports::msvcrt::round as *const () as usize,
            "roundf" => imports::msvcrt::roundf as *const () as usize,
            "sinf" => imports::msvcrt::sinf as *const () as usize,
            "sinhf" => imports::msvcrt::sinhf as *const () as usize,
            "sqrtf" => imports::msvcrt::sqrtf as *const () as usize,
            "tanf" => imports::msvcrt::tanf as *const () as usize,
            "tanhf" => imports::msvcrt::tanhf as *const () as usize,
            "trunc" => imports::msvcrt::trunc as *const () as usize,
            "truncf" => imports::msvcrt::truncf as *const () as usize,
            "fegetround" => imports::msvcrt::fegetround as *const () as usize,
            "fesetround" => imports::msvcrt::fesetround as *const () as usize,
            "_controlfp_s" => imports::msvcrt::_controlfp_s as *const () as usize,
            "islower" => imports::msvcrt::islower as *const () as usize,
            "isupper" => imports::msvcrt::isupper as *const () as usize,
            "isprint" => imports::msvcrt::isprint as *const () as usize,
            "iswalnum" => imports::msvcrt::iswalnum as *const () as usize,
            "iswspace" => imports::msvcrt::iswspace as *const () as usize,
            "iswxdigit" => imports::msvcrt::iswxdigit as *const () as usize,
            "strcpy" => imports::msvcrt::strcpy as *const () as usize,
            "strncpy" => imports::msvcrt::strncpy as *const () as usize,
            "strcspn" => imports::msvcrt::strcspn as *const () as usize,
            "strpbrk" => imports::msvcrt::strpbrk as *const () as usize,
            "__strncnt" => imports::msvcrt::__strncnt as *const () as usize,
            "wcslen" => imports::msvcrt::wcslen as *const () as usize,
            "wcsnlen" => imports::msvcrt::wcsnlen as *const () as usize,
            "wcscmp" => imports::msvcrt::wcscmp as *const () as usize,
            "atol" => imports::msvcrt::atol as *const () as usize,
            "strtol" => imports::msvcrt::strtol as *const () as usize,
            "strtoll" => imports::msvcrt::strtoll as *const () as usize,
            "strtoull" => imports::msvcrt::strtoull as *const () as usize,
            "strtof" => imports::msvcrt::strtof as *const () as usize,
            "btowc" => imports::msvcrt::btowc as *const () as usize,
            "realloc" => imports::msvcrt::realloc as *const () as usize,
            "_recalloc" => imports::msvcrt::_recalloc as *const () as usize,
            "rand" => imports::msvcrt::rand as *const () as usize,
            "rand_s" => imports::msvcrt::rand_s as *const () as usize,
            "_wgetcwd" => imports::msvcrt::_wgetcwd as *const () as usize,
            "abort" => imports::msvcrt::abort as *const () as usize,
            "exit" => imports::msvcrt::exit as *const () as usize,
            "_invalid_parameter_noinfo_noreturn" => {
                imports::msvcrt::_invalid_parameter_noinfo_noreturn as *const () as usize
            }
            "_invoke_watson" => imports::msvcrt::_invoke_watson as *const () as usize,
            "_resetstkoflw" => imports::msvcrt::_resetstkoflw as *const () as usize,
            "_set_new_handler" => imports::msvcrt::_set_new_handler as *const () as usize,
            "_crt_at_quick_exit" => imports::msvcrt::_crt_at_quick_exit as *const () as usize,
            "___lc_codepage_func" => imports::msvcrt::___lc_codepage_func as *const () as usize,
            "___lc_collate_cp_func" => imports::msvcrt::___lc_collate_cp_func as *const () as usize,
            "___lc_locale_name_func" => {
                imports::msvcrt::___lc_locale_name_func as *const () as usize
            }
            "___mb_cur_max_func" => imports::msvcrt::___mb_cur_max_func as *const () as usize,
            "__pctype_func" => imports::msvcrt::__pctype_func as *const () as usize,
            "_lock_locales" => imports::msvcrt::_lock_locales as *const () as usize,
            "_unlock_locales" => imports::msvcrt::_unlock_locales as *const () as usize,
            "localeconv" => imports::msvcrt::localeconv as *const () as usize,
            "__acrt_iob_func" => imports::msvcrt::__acrt_iob_func as *const () as usize,
            "fflush" => imports::msvcrt::fflush as *const () as usize,
            "fgetc" => imports::msvcrt::fgetc as *const () as usize,
            "fputc" => imports::msvcrt::fputc as *const () as usize,
            "fputs" => imports::msvcrt::fputs as *const () as usize,
            "puts" => imports::msvcrt::puts as *const () as usize,
            "ungetc" => imports::msvcrt::ungetc as *const () as usize,
            "fwrite" => imports::msvcrt::fwrite as *const () as usize,
            "setvbuf" => imports::msvcrt::setvbuf as *const () as usize,
            "_fseeki64" => imports::msvcrt::_fseeki64 as *const () as usize,
            "fgetpos" => imports::msvcrt::fgetpos as *const () as usize,
            "fsetpos" => imports::msvcrt::fsetpos as *const () as usize,
            "_lock_file" => imports::msvcrt::_lock_file as *const () as usize,
            "_unlock_file" => imports::msvcrt::_unlock_file as *const () as usize,
            "_fsopen" => imports::msvcrt::_fsopen as *const () as usize,
            "_setmode" => imports::msvcrt::_setmode as *const () as usize,
            "_lseek" => imports::msvcrt::_lseek as *const () as usize,
            "__stdio_common_vfprintf" => {
                imports::msvcrt::__stdio_common_vfprintf as *const () as usize
            }
            "_get_stream_buffer_pointers" => {
                imports::msvcrt::_get_stream_buffer_pointers as *const () as usize
            }
            _ => 0,
        }
    }

    fn resolve_kernel32(name: &str) -> usize {
        match name {
            // memory
            "VirtualAlloc" => imports::kernel32::VirtualAlloc as *const () as usize,
            "VirtualFree" => imports::kernel32::VirtualFree as *const () as usize,
            "GetProcessHeap" => imports::kernel32::GetProcessHeap as *const () as usize,
            "HeapCreate" => imports::kernel32::HeapCreate as *const () as usize,
            "HeapDestroy" => imports::kernel32::HeapDestroy as *const () as usize,
            "HeapAlloc" => imports::kernel32::HeapAlloc as *const () as usize,
            "HeapFree" => imports::kernel32::HeapFree as *const () as usize,
            "LocalAlloc" => imports::kernel32::LocalAlloc as *const () as usize,
            "LocalFree" => imports::kernel32::LocalFree as *const () as usize,

            // file
            "CreateFileW" => imports::kernel32::CreateFileW as *const () as usize,
            "CreateFileA" => imports::kernel32::CreateFileA as *const () as usize,
            "ReadFile" => imports::kernel32::ReadFile as *const () as usize,
            "WriteFile" => imports::kernel32::WriteFile as *const () as usize,
            "CloseHandle" => imports::kernel32::CloseHandle as *const () as usize,
            "CreateEventW" => imports::kernel32::CreateEventW as *const () as usize,
            "SetEvent" => imports::kernel32::SetEvent as *const () as usize,
            "ResetEvent" => imports::kernel32::ResetEvent as *const () as usize,
            "WaitForSingleObjectEx" => {
                imports::kernel32::WaitForSingleObjectEx as *const () as usize
            }
            "GetModuleHandleW" => imports::kernel32::GetModuleHandleW as *const () as usize,
            "InitializeSListHead" => imports::kernel32::InitializeSListHead as *const () as usize,
            "GetFileSize" => imports::kernel32::GetFileSize as *const () as usize,
            "GetFileSizeEx" => imports::kernel32::GetFileSizeEx as *const () as usize,
            "GetFileType" => imports::kernel32::GetFileType as *const () as usize,
            "SetFilePointer" => imports::kernel32::SetFilePointer as *const () as usize,
            "SetFilePointerEx" => imports::kernel32::SetFilePointerEx as *const () as usize,
            "SetEndOfFile" => imports::kernel32::SetEndOfFile as *const () as usize,
            "CopyFileExW" => imports::kernel32::CopyFileExW as *const () as usize,
            "DeleteFileW" => imports::kernel32::DeleteFileW as *const () as usize,
            "GetFileAttributesW" => imports::kernel32::GetFileAttributesW as *const () as usize,
            "SetFileAttributesW" => imports::kernel32::SetFileAttributesW as *const () as usize,
            "GetFullPathNameW" => imports::kernel32::GetFullPathNameW as *const () as usize,
            "GetFullPathNameA" => imports::kernel32::GetFullPathNameA as *const () as usize,
            "CreateFileMappingW" => imports::kernel32::CreateFileMappingW as *const () as usize,
            "MapViewOfFile" => imports::kernel32::MapViewOfFile as *const () as usize,
            "MapViewOfFileEx" => imports::kernel32::MapViewOfFileEx as *const () as usize,
            "UnmapViewOfFile" => imports::kernel32::UnmapViewOfFile as *const () as usize,
            "FlushViewOfFile" => imports::kernel32::FlushViewOfFile as *const () as usize,
            "DeviceIoControl" => imports::kernel32::DeviceIoControl as *const () as usize,

            // sync
            "InitializeCriticalSection" => {
                imports::kernel32::InitializeCriticalSection as *const () as usize
            }
            "InitializeCriticalSectionAndSpinCount" => {
                imports::kernel32::InitializeCriticalSectionAndSpinCount as *const () as usize
            }
            "DeleteCriticalSection" => {
                imports::kernel32::DeleteCriticalSection as *const () as usize
            }
            "EnterCriticalSection" => imports::kernel32::EnterCriticalSection as *const () as usize,
            "LeaveCriticalSection" => imports::kernel32::LeaveCriticalSection as *const () as usize,
            "Sleep" => imports::kernel32::Sleep as *const () as usize,

            // TLS
            "TlsAlloc" => imports::kernel32::TlsAlloc as *const () as usize,
            "TlsFree" => imports::kernel32::TlsFree as *const () as usize,
            "TlsGetValue" => imports::kernel32::TlsGetValue as *const () as usize,
            "TlsSetValue" => imports::kernel32::TlsSetValue as *const () as usize,

            // misc
            "GetLastError" => imports::kernel32::GetLastError as *const () as usize,
            "SetLastError" => imports::kernel32::SetLastError as *const () as usize,
            "GetCurrentProcessId" => imports::kernel32::GetCurrentProcessId as *const () as usize,
            "GetCurrentThreadId" => imports::kernel32::GetCurrentThreadId as *const () as usize,
            "GetCurrentProcess" => imports::kernel32::GetCurrentProcess as *const () as usize,
            "GetTickCount" => imports::kernel32::GetTickCount as *const () as usize,
            "QueryPerformanceCounter" => {
                imports::kernel32::QueryPerformanceCounter as *const () as usize
            }
            "GetSystemTimeAsFileTime" => {
                imports::kernel32::GetSystemTimeAsFileTime as *const () as usize
            }
            "GetSystemInfo" => imports::kernel32::GetSystemInfo as *const () as usize,
            "OutputDebugStringA" => imports::kernel32::OutputDebugStringA as *const () as usize,
            "DisableThreadLibraryCalls" => {
                imports::kernel32::DisableThreadLibraryCalls as *const () as usize
            }
            "FreeLibrary" => imports::kernel32::FreeLibrary as *const () as usize,
            "LoadLibraryExW" => imports::kernel32::LoadLibraryExW as *const () as usize,
            "LoadLibraryW" => imports::kernel32::LoadLibraryW as *const () as usize,
            "LoadLibraryA" => imports::kernel32::LoadLibraryA as *const () as usize,
            "GetProcAddress" => imports::kernel32::GetProcAddress as *const () as usize,
            "GetModuleFileNameA" => imports::kernel32::GetModuleFileNameA as *const () as usize,
            "GetEnvironmentVariableA" => {
                imports::kernel32::GetEnvironmentVariableA as *const () as usize
            }
            "ExpandEnvironmentStringsW" => {
                imports::kernel32::ExpandEnvironmentStringsW as *const () as usize
            }
            "MultiByteToWideChar" => imports::kernel32::MultiByteToWideChar as *const () as usize,
            "WideCharToMultiByte" => imports::kernel32::WideCharToMultiByte as *const () as usize,
            "LCMapStringW" => imports::kernel32::LCMapStringW as *const () as usize,
            "lstrcmpiA" => imports::kernel32::lstrcmpiA as *const () as usize,
            "TerminateProcess" => imports::kernel32::TerminateProcess as *const () as usize,
            "UnhandledExceptionFilter" => {
                imports::kernel32::UnhandledExceptionFilter as *const () as usize
            }
            "SetUnhandledExceptionFilter" => {
                imports::kernel32::SetUnhandledExceptionFilter as *const () as usize
            }
            "GetVersion" => imports::kernel32::GetVersion as *const () as usize,
            "IsDebuggerPresent" => imports::kernel32::IsDebuggerPresent as *const () as usize,
            "IsProcessorFeaturePresent" => {
                imports::kernel32::IsProcessorFeaturePresent as *const () as usize
            }
            "HeapReAlloc" => imports::kernel32::HeapReAlloc as *const () as usize,
            "HeapSize" => imports::kernel32::HeapSize as *const () as usize,
            "InitializeSRWLock" => imports::kernel32::InitializeSRWLock as *const () as usize,
            "AcquireSRWLockExclusive" => {
                imports::kernel32::AcquireSRWLockExclusive as *const () as usize
            }
            "AcquireSRWLockShared" => imports::kernel32::AcquireSRWLockShared as *const () as usize,
            "TryAcquireSRWLockExclusive" => {
                imports::kernel32::TryAcquireSRWLockExclusive as *const () as usize
            }
            "TryAcquireSRWLockShared" => {
                imports::kernel32::TryAcquireSRWLockShared as *const () as usize
            }
            "ReleaseSRWLockExclusive" => {
                imports::kernel32::ReleaseSRWLockExclusive as *const () as usize
            }
            "ReleaseSRWLockShared" => imports::kernel32::ReleaseSRWLockShared as *const () as usize,
            "InitializeConditionVariable" => {
                imports::kernel32::InitializeConditionVariable as *const () as usize
            }
            "SleepConditionVariableSRW" => {
                imports::kernel32::SleepConditionVariableSRW as *const () as usize
            }
            "SleepConditionVariableCS" => {
                imports::kernel32::SleepConditionVariableCS as *const () as usize
            }
            "WakeConditionVariable" => {
                imports::kernel32::WakeConditionVariable as *const () as usize
            }
            "WakeAllConditionVariable" => {
                imports::kernel32::WakeAllConditionVariable as *const () as usize
            }
            "InitOnceExecuteOnce" => imports::kernel32::InitOnceExecuteOnce as *const () as usize,
            "InitializeCriticalSectionEx" => {
                imports::kernel32::InitializeCriticalSectionEx as *const () as usize
            }
            "TryEnterCriticalSection" => {
                imports::kernel32::TryEnterCriticalSection as *const () as usize
            }
            "EncodePointer" => imports::kernel32::EncodePointer as *const () as usize,
            "DecodePointer" => imports::kernel32::DecodePointer as *const () as usize,
            "GetStartupInfoW" => imports::kernel32::GetStartupInfoW as *const () as usize,
            "GetModuleHandleExW" => imports::kernel32::GetModuleHandleExW as *const () as usize,
            "GetModuleFileNameW" => imports::kernel32::GetModuleFileNameW as *const () as usize,
            "GetEnvironmentVariableW" => {
                imports::kernel32::GetEnvironmentVariableW as *const () as usize
            }
            "QueryPerformanceFrequency" => {
                imports::kernel32::QueryPerformanceFrequency as *const () as usize
            }
            "GetTickCount64" => imports::kernel32::GetTickCount64 as *const () as usize,
            "GetCurrentProcessorNumber" => {
                imports::kernel32::GetCurrentProcessorNumber as *const () as usize
            }
            "SwitchToThread" => imports::kernel32::SwitchToThread as *const () as usize,
            "FlushProcessWriteBuffers" => {
                imports::kernel32::FlushProcessWriteBuffers as *const () as usize
            }
            "GetNativeSystemInfo" => imports::kernel32::GetNativeSystemInfo as *const () as usize,
            "AreFileApisANSI" => imports::kernel32::AreFileApisANSI as *const () as usize,
            "SetErrorMode" => imports::kernel32::SetErrorMode as *const () as usize,
            "OutputDebugStringW" => imports::kernel32::OutputDebugStringW as *const () as usize,
            "CreateEventExW" => imports::kernel32::CreateEventExW as *const () as usize,
            "WaitForSingleObject" => imports::kernel32::WaitForSingleObject as *const () as usize,
            "AddVectoredExceptionHandler" => {
                imports::kernel32::AddVectoredExceptionHandler as *const () as usize
            }
            "RemoveVectoredExceptionHandler" => {
                imports::kernel32::RemoveVectoredExceptionHandler as *const () as usize
            }
            "RtlCaptureStackBackTrace" => {
                imports::kernel32::RtlCaptureStackBackTrace as *const () as usize
            }

            "RtlCaptureContext" | "RtlLookupFunctionEntry" | "RtlVirtualUnwind" => {
                resolve_ntdll(name)
            }
            _ => 0,
        }
    }

    fn resolve_advapi32(name: &str) -> usize {
        match name {
            // registry
            "RegOpenKeyExA" => imports::advapi32::RegOpenKeyExA as *const () as usize,
            "RegOpenKeyExW" => imports::advapi32::RegOpenKeyExW as *const () as usize,
            "RegQueryValueExA" => imports::advapi32::RegQueryValueExA as *const () as usize,
            "RegQueryValueExW" => imports::advapi32::RegQueryValueExW as *const () as usize,
            "RegEnumKeyExA" => imports::advapi32::RegEnumKeyExA as *const () as usize,
            "RegCloseKey" => imports::advapi32::RegCloseKey as *const () as usize,

            // crypto
            "CryptAcquireContextW" => imports::advapi32::CryptAcquireContextW as *const () as usize,
            "CryptReleaseContext" => imports::advapi32::CryptReleaseContext as *const () as usize,
            "CryptCreateHash" => imports::advapi32::CryptCreateHash as *const () as usize,
            "CryptDestroyHash" => imports::advapi32::CryptDestroyHash as *const () as usize,
            "CryptHashData" => imports::advapi32::CryptHashData as *const () as usize,
            "CryptGetHashParam" => imports::advapi32::CryptGetHashParam as *const () as usize,
            "EventRegister" => imports::advapi32::EventRegister as *const () as usize,
            "EventUnregister" => imports::advapi32::EventUnregister as *const () as usize,
            "EventWriteTransfer" => imports::advapi32::EventWriteTransfer as *const () as usize,
            _ => 0,
        }
    }

    fn resolve_ntdll(name: &str) -> usize {
        match name {
            "RtlCaptureContext" => imports::ntdll::RtlCaptureContext as *const () as usize,
            "RtlLookupFunctionEntry" => {
                imports::ntdll::RtlLookupFunctionEntry as *const () as usize
            }
            "RtlVirtualUnwind" => imports::ntdll::RtlVirtualUnwind as *const () as usize,
            "RtlUnwindEx" => imports::ntdll::RtlUnwindEx as *const () as usize,
            "RaiseException" => imports::ntdll::RaiseException as *const () as usize,
            "RtlPcToFileHeader" => imports::ntdll::RtlPcToFileHeader as *const () as usize,
            "RtlUnwind" => imports::ntdll::RtlUnwind as *const () as usize,
            _ => 0,
        }
    }

    fn resolve_ole32(name: &str) -> usize {
        match name {
            "CoGetMalloc" => imports::ole32::CoGetMalloc as *const () as usize,
            "CoTaskMemAlloc" => imports::ole32::CoTaskMemAlloc as *const () as usize,
            "CoTaskMemRealloc" => imports::ole32::CoTaskMemRealloc as *const () as usize,
            "CoTaskMemFree" => imports::ole32::CoTaskMemFree as *const () as usize,
            "SysAllocString" => imports::ole32::SysAllocString as *const () as usize,
            "SysAllocStringLen" => imports::ole32::SysAllocStringLen as *const () as usize,
            "SysAllocStringByteLen" => imports::ole32::SysAllocStringByteLen as *const () as usize,
            "SysFreeString" => imports::ole32::SysFreeString as *const () as usize,
            "SysStringLen" => imports::ole32::SysStringLen as *const () as usize,
            "SysStringByteLen" => imports::ole32::SysStringByteLen as *const () as usize,
            "SetErrorInfo" => imports::ole32::SetErrorInfo as *const () as usize,
            "GetErrorInfo" => imports::ole32::GetErrorInfo as *const () as usize,
            _ => 0,
        }
    }

    fn resolve_rpcrt4(name: &str) -> usize {
        match name {
            "UuidCreate" => imports::rpcrt4::UuidCreate as *const () as usize,
            _ => 0,
        }
    }
}
