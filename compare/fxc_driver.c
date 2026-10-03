/*
 * fxc_driver <d3dcompiler library> <job file>
 *
 * Compiles every job in the file with D3DCompile and writes the bytecode. Built twice from this one
 * source: for Linux against libd3dcompiler.so, and for Windows (MinGW) against d3dcompiler_47.dll,
 * where it runs under Wine. Each job line is
 *
 *     <source>|<entry point>|<target>|<flags1, hex>|<output>
 *
 * #include is resolved relative to the source's folder. A job that fails to compile writes no
 * output; its errors go to stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define LOAD(path) ((void*)LoadLibraryA(path))
#define SYMBOL(lib, name) ((void*)GetProcAddress((HMODULE)(lib), name))
#define CALL __stdcall
#else
#include <dlfcn.h>
#define LOAD(path) dlopen(path, RTLD_NOW)
#define SYMBOL(lib, name) dlsym(lib, name)
#define CALL
#endif

typedef struct Blob Blob;
struct BlobVtbl {
    void* QueryInterface;
    unsigned (CALL *AddRef)(Blob*);
    unsigned (CALL *Release)(Blob*);
    void* (CALL *GetBufferPointer)(Blob*);
    size_t (CALL *GetBufferSize)(Blob*);
};
struct Blob { struct BlobVtbl* v; };

typedef struct Include Include;
struct IncludeVtbl {
    int (CALL *Open)(Include*, int type, const char* name, const void* parent, const void** data, unsigned* bytes);
    int (CALL *Close)(Include*, const void* data);
};
struct Include { struct IncludeVtbl* v; char dir[4096]; };

typedef int (CALL *PD3DCompile)(const void*, size_t, const char*, const void*, Include*, const char*,
                                const char*, unsigned, unsigned, Blob**, Blob**);

static char* read_file(const char* path, long* size) {
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

static int CALL include_open(Include* self, int type, const char* name, const void* parent, const void** data, unsigned* bytes) {
    (void)type; (void)parent;
    char path[8192];
    snprintf(path, sizeof path, "%s/%s", self->dir, name);
    long n;
    char* contents = read_file(path, &n);
    if (!contents) return (int)0x80004005; /* E_FAIL */
    *data = contents;
    *bytes = (unsigned)n;
    return 0;
}

static int CALL include_close(Include* self, const void* data) {
    (void)self;
    free((void*)data);
    return 0;
}

static struct IncludeVtbl include_vtbl = { include_open, include_close };

int main(int argc, char** argv) {
    if (argc != 3) { fprintf(stderr, "usage: fxc_driver <d3dcompiler library> <job file>\n"); return 2; }
    void* lib = LOAD(argv[1]);
    if (!lib) { fprintf(stderr, "cannot load %s\n", argv[1]); return 2; }
    PD3DCompile compile = (PD3DCompile)SYMBOL(lib, "D3DCompile");
    FILE* jobs = fopen(argv[2], "r");
    if (!compile || !jobs) { fprintf(stderr, "no D3DCompile or no job file\n"); return 2; }

    char line[16384];
    int compiled = 0, failed = 0;
    while (fgets(line, sizeof line, jobs)) {
        line[strcspn(line, "\r\n")] = 0;
        char* field[5];
        int k = 0;
        field[k++] = line;
        for (char* p = line; *p && k < 5; p++)
            if (*p == '|') { *p = 0; field[k++] = p + 1; }
        if (k != 5) continue;

        long n;
        char* source = read_file(field[0], &n);
        if (!source) { fprintf(stderr, "%s: cannot read\n", field[0]); failed++; continue; }
        Include include = { &include_vtbl, "" };
        snprintf(include.dir, sizeof include.dir, "%s", field[0]);
        char* slash = strrchr(include.dir, '/');
        char* backslash = strrchr(include.dir, '\\');
        if (backslash > slash) slash = backslash;
        if (slash) *slash = 0; else strcpy(include.dir, ".");

        Blob* code = NULL;
        Blob* errors = NULL;
        int hr = compile(source, (size_t)n, field[0], NULL, &include, field[1], field[2],
                         (unsigned)strtoul(field[3], NULL, 16), 0, &code, &errors);
        if (hr >= 0 && code) {
            FILE* out = fopen(field[4], "wb");
            fwrite(code->v->GetBufferPointer(code), 1, code->v->GetBufferSize(code), out);
            fclose(out);
            compiled++;
        } else {
            failed++;
            if (errors) fprintf(stderr, "%s: %.400s\n", field[0], (const char*)errors->v->GetBufferPointer(errors));
        }
        if (code) code->v->Release(code);
        if (errors) errors->v->Release(errors);
        free(source);
    }
    printf("compiled %d failed %d\n", compiled, failed);
    return 0;
}
