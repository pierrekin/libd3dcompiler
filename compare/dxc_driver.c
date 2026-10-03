/*
 * dxc_driver <libd3dcompiler library, or - on Windows> <DLL folder> <job file>
 *
 * Compiles every job in the file with DXC's IDxcCompiler3 and writes the object, signed by dxil.dll.
 * Built twice from this one source: for Linux, where libd3dcompiler's PE loader maps the DLL folder's
 * dxcompiler.dll and Microsoft's C++ runtime, and for Windows (MinGW), where it runs under Wine with
 * the same DLLs beside it. Each job line is
 *
 *     <source>|<output>|<argument>|<argument>|...
 *
 * and the source's file name is passed as the last argument, as dxc.exe passes it. #include is
 * resolved relative to the including source's folder. A job that fails to compile writes no output;
 * its errors go to stderr.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define CALL
typedef wchar_t wchar16;
#else
#include <dlfcn.h>
#define CALL __attribute__((ms_abi))
typedef uint16_t wchar16;
#endif

typedef struct { uint32_t a; uint16_t b, c; uint8_t d[8]; } Guid;
typedef struct { const void* ptr; size_t size; uint32_t encoding; } DxcBuffer;
typedef void** Object;
#define METHOD(object, index, type) ((type)(*(void***)(object))[index])

static const Guid CLSID_DxcCompiler = {0x73e22d93, 0xe6ce, 0x47f3, {0xb5, 0xbf, 0xf0, 0x66, 0x4f, 0x39, 0xc1, 0xb0}};
static const Guid IID_IDxcCompiler3 = {0x228b4687, 0x5a6a, 0x4730, {0x90, 0x0c, 0x97, 0x02, 0xb2, 0x20, 0x3f, 0x54}};
static const Guid CLSID_DxcUtils = {0x6245d6af, 0x66e0, 0x48fd, {0x80, 0xb4, 0x4d, 0x27, 0x17, 0x96, 0x74, 0x8c}};
static const Guid IID_IDxcUtils = {0x4605c4cb, 0x2019, 0x492a, {0xad, 0xa4, 0x65, 0xf2, 0x0b, 0xb7, 0xd6, 0x7f}};
static const Guid IID_IDxcResult = {0x58346cda, 0xdde7, 0x4497, {0x94, 0x61, 0x6f, 0x87, 0xaf, 0x5e, 0x06, 0x59}};
static const Guid IID_IDxcIncludeHandler = {0x7f61fc7d, 0x950d, 0x467f, {0xb3, 0xe3, 0x3c, 0x02, 0xfb, 0x49, 0x18, 0x7c}};

typedef int32_t (CALL *CreateInstance)(const Guid*, const Guid*, void**);

static char* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* data = malloc(n + 1);
    if (fread(data, 1, n, f) != (size_t)n) { fclose(f); free(data); return NULL; }
    fclose(f);
    data[n] = 0;
    *size = n;
    return data;
}

static wchar16* widen(const char* s) {
    size_t n = strlen(s);
    wchar16* w = calloc(n + 1, sizeof(wchar16));
    for (size_t i = 0; i < n; i++) w[i] = (unsigned char)s[i];
    return w;
}

/* An IDxcIncludeHandler that reads includes relative to the source's folder */
typedef struct Include Include;
struct IncludeVtbl {
    int32_t (CALL *QueryInterface)(Include*, const Guid*, void**);
    uint32_t (CALL *AddRef)(Include*);
    uint32_t (CALL *Release)(Include*);
    int32_t (CALL *LoadSource)(Include*, const wchar16* name, void** blob);
};
struct Include { struct IncludeVtbl* v; Object utils; char dir[4096]; };

static int32_t CALL include_query(Include* self, const Guid* iid, void** out) {
    if (!memcmp(iid, &IID_IDxcIncludeHandler, sizeof(Guid))) { *out = self; return 0; }
    *out = NULL;
    return (int32_t)0x80004002; /* E_NOINTERFACE */
}

static uint32_t CALL include_ref(Include* self) { (void)self; return 1; }

static int32_t CALL include_load(Include* self, const wchar16* name, void** blob) {
    char path[8192];
    size_t n = strlen(self->dir);
    memcpy(path, self->dir, n);
    path[n++] = '/';
    const wchar16* c = name;
    if (c[0] == '.' && (c[1] == '/' || c[1] == '\\')) c += 2;
    for (; *c && n < sizeof path - 1; c++) path[n++] = *c == '\\' ? '/' : (char)*c;
    path[n] = 0;
    size_t size;
    char* contents = read_file(path, &size);
    *blob = NULL;
    if (!contents) return (int32_t)0x80070002; /* file not found */
    int32_t hr = METHOD(self->utils, 6, int32_t (CALL *)(Object, const void*, uint32_t, uint32_t, void**))(
        self->utils, contents, (uint32_t)size, 65001, blob); /* IDxcUtils::CreateBlob, UTF-8 */
    free(contents);
    return hr;
}

static struct IncludeVtbl include_vtbl = { include_query, include_ref, include_ref, include_load };

int main(int argc, char** argv) {
    if (argc != 4) { fprintf(stderr, "usage: dxc_driver <libd3dcompiler library, or - on Windows> <DLL folder> <job file>\n"); return 2; }
    char path[4096];
#ifdef _WIN32
    snprintf(path, sizeof path, "%s\\dxcompiler.dll", argv[2]);
    HMODULE dxc = LoadLibraryA(path);
    CreateInstance create = dxc ? (CreateInstance)GetProcAddress(dxc, "DxcCreateInstance") : NULL;
#else
    void* loader = dlopen(argv[1], RTLD_NOW);
    if (!loader) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    void* (*load)(const char*) = (void* (*)(const char*))dlsym(loader, "pe_load_library");
    void* (*find)(void*, const char*) = (void* (*)(void*, const char*))dlsym(loader, "pe_get_proc_address");
    const char* runtime[] = { "VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll" };
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof path, "%s/%s", argv[2], runtime[i]);
        if (!load(path)) { fprintf(stderr, "cannot load %s\n", path); return 2; }
    }
    snprintf(path, sizeof path, "%s/dxcompiler.dll", argv[2]);
    void* dxc = load(path);
    CreateInstance create = dxc ? (CreateInstance)find(dxc, "DxcCreateInstance") : NULL;
#endif
    if (!create) { fprintf(stderr, "cannot load %s\n", path); return 2; }
    Object compiler = NULL, utils = NULL;
    if (create(&CLSID_DxcCompiler, &IID_IDxcCompiler3, (void**)&compiler) < 0 ||
        create(&CLSID_DxcUtils, &IID_IDxcUtils, (void**)&utils) < 0) {
        fprintf(stderr, "DxcCreateInstance failed\n");
        return 2;
    }
    FILE* jobs = fopen(argv[3], "r");
    if (!jobs) { fprintf(stderr, "cannot read %s\n", argv[3]); return 2; }

    static char line[65536];
    int compiled = 0, failed = 0;
    while (fgets(line, sizeof line, jobs)) {
        line[strcspn(line, "\r\n")] = 0;
        char* field[256];
        int k = 0;
        field[k++] = line;
        for (char* p = line; *p && k < 255; p++)
            if (*p == '|') { *p = 0; field[k++] = p + 1; }
        if (k < 2) continue;

        size_t size;
        char* source = read_file(field[0], &size);
        if (!source) { fprintf(stderr, "%s: cannot read\n", field[0]); failed++; continue; }
        Include include = { &include_vtbl, utils, "" };
        snprintf(include.dir, sizeof include.dir, "%s", field[0]);
        char* slash = strrchr(include.dir, '/');
        char* backslash = strrchr(include.dir, '\\');
        if (backslash > slash) slash = backslash;
        const char* file_name = slash ? field[0] + (slash - include.dir) + 1 : field[0];
        if (slash) *slash = 0; else strcpy(include.dir, ".");

        int count = k - 2;
        wchar16* args[257];
        for (int i = 0; i < count; i++) args[i] = widen(field[2 + i]);
        args[count++] = widen(file_name);
        DxcBuffer buffer = { source, size, 0 };
        Object result = NULL;
        int32_t status = METHOD(compiler, 3, int32_t (CALL *)(Object, const DxcBuffer*, wchar16**, uint32_t, Include*, const Guid*, void**))(
            compiler, &buffer, args, (uint32_t)count, &include, &IID_IDxcResult, (void**)&result);
        if (status >= 0) METHOD(result, 3, int32_t (CALL *)(Object, int32_t*))(result, &status); /* GetStatus */
        if (status >= 0) {
            Object object = NULL;
            METHOD(result, 4, int32_t (CALL *)(Object, Object*))(result, &object); /* GetResult */
            FILE* out = fopen(field[1], "wb");
            fwrite(METHOD(object, 3, void* (CALL *)(Object))(object), 1, METHOD(object, 4, size_t (CALL *)(Object))(object), out);
            fclose(out);
            METHOD(object, 2, uint32_t (CALL *)(Object))(object);
            compiled++;
        } else {
            failed++;
            Object errors = NULL;
            if (result) METHOD(result, 5, int32_t (CALL *)(Object, Object*))(result, &errors); /* GetErrorBuffer */
            if (errors && METHOD(errors, 4, size_t (CALL *)(Object))(errors))
                fprintf(stderr, "%s: %.400s\n", field[0], (const char*)METHOD(errors, 3, void* (CALL *)(Object))(errors));
            if (errors) METHOD(errors, 2, uint32_t (CALL *)(Object))(errors);
        }
        if (result) METHOD(result, 2, uint32_t (CALL *)(Object))(result);
        for (int i = 0; i < count; i++) free(args[i]);
        free(source);
    }
    printf("compiled %d failed %d\n", compiled, failed);
    return 0;
}
