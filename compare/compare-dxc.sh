#!/usr/bin/env bash
# Compiles the same shaders with dxcompiler.dll and dxil.dll on Linux, through libd3dcompiler's PE
# loader, and on Windows, under Wine, and compares the signed objects:
#
#   compare-dxc.sh <DXC folder> <C++ runtime folder> <job file> <out dir>
#
# The DXC folder holds dxcompiler.dll and dxil.dll; the runtime folder Microsoft's MSVCP140.dll,
# VCRUNTIME140.dll and VCRUNTIME140_1.dll, which both sides use, so Wine's own runtime stays out. A
# job line is <source>|<argument>|<argument>|... (see dxc_driver.c); the outputs are named by line
# number. Writes <out dir>/results.csv with each job's source and output hashes and its outcome, and
# prints a summary. Needs cargo, cc, x86_64-w64-mingw32-gcc and Wine (WINE, or `wine` on the PATH).
# JOBS sets how many processes each side runs (default: half the CPUs).
set -euo pipefail
dxc=$(realpath "$1"); runtime=$(realpath "$2"); jobfile=$(realpath "$3"); out=$(realpath -m "$4")
here=$(cd "$(dirname "$0")" && pwd); root=$(dirname "$here")
WINE=${WINE:-wine}
JOBS=${JOBS:-$(( $(nproc) / 2 ))}
mkdir -p "$out/dlls"

(cd "$root" && cargo build --release -p d3dcompiler >/dev/null)
cc -O2 -o "$out/dxc_driver" "$here/dxc_driver.c" -ldl
x86_64-w64-mingw32-gcc -O2 -o "$out/dxc_driver.exe" "$here/dxc_driver.c"
cp "$dxc/dxcompiler.dll" "$dxc/dxil.dll" "$runtime/MSVCP140.dll" "$runtime/VCRUNTIME140.dll" "$runtime/VCRUNTIME140_1.dll" "$out/dlls/"
# the Windows side finds the DLLs beside the driver
cp "$out"/dlls/*.dll "$out/"

winpath() { printf 'Z:%s' "$(printf '%s' "$1" | tr '/' '\\')"; }
# one job file per process and side, every JOBS-th line, so slow shaders spread out
awk -F'|' -v out="$out" -v n="$JOBS" '{ k = (NR - 1) % n; rest = substr($0, length($1) + 1)
    print $1 "|" out "/" NR ".linux" rest > (out "/linux-" k ".jobs")
    print $1 "|" out "/" NR ".windows" rest > (out "/windows-" k ".jobs") }' "$jobfile"
# arguments with a / in them would be mangled here; these jobs have none
sed -i -E 's#^([^|]*)\|([^|]*)#Z:\1|Z:\2#; s#/#\\#g' "$out"/windows-*.jobs

for k in $(seq 0 $((JOBS - 1))); do
    [ -s "$out/linux-$k.jobs" ] || continue
    "$out/dxc_driver" "$root/target/release/libd3dcompiler.so" "$out/dlls" "$out/linux-$k.jobs" >"$out/linux-$k.log" 2>&1 &
    WINEDEBUG=-all WINEDLLOVERRIDES="msvcp140,vcruntime140,vcruntime140_1=n" \
        "$WINE" "$out/dxc_driver.exe" - "$(winpath "$out")" "$(winpath "$out/windows-$k.jobs")" >"$out/windows-$k.log" 2>&1 &
done
wait

echo "job,source_sha256,arguments,windows_sha256,linux_sha256,outcome" >"$out/results.csv"
n=0
while IFS='|' read -r src args; do
    n=$((n + 1))
    w=$out/$n.windows; l=$out/$n.linux
    hw=$([ -f "$w" ] && sha256sum <"$w" | cut -c1-64 || true)
    hl=$([ -f "$l" ] && sha256sum <"$l" | cut -c1-64 || true)
    if [ -z "$hw$hl" ]; then outcome="both failed"
    elif [ -z "$hl" ]; then outcome="only windows compiled"
    elif [ -z "$hw" ]; then outcome="only linux compiled"
    elif [ "$hw" = "$hl" ]; then outcome=identical
    else outcome=different; fi
    echo "$n,$(sha256sum <"$src" | cut -c1-64),${args//|/ },$hw,$hl,$outcome" >>"$out/results.csv"
done <"$jobfile"
tail -n +2 "$out/results.csv" | cut -d, -f6 | sort | uniq -c
