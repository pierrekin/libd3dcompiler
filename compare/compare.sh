#!/usr/bin/env bash
# Compiles the same shaders with d3dcompiler_47.dll on Linux, through libd3dcompiler, and on Windows,
# under Wine, and compares the bytecode:
#
#   compare.sh <d3dcompiler_47.dll> <job file> <out dir>
#
# A job line is <source>|<entry point>|<target>|<flags1, hex> (see fxc_driver.c); the outputs are
# named by line number. Writes <out dir>/results.csv with each job's source and output hashes and
# its outcome, and prints a summary. Needs cargo, cc, x86_64-w64-mingw32-gcc and Wine (WINE, or
# `wine` on the PATH). JOBS sets how many processes each side runs (default: half the CPUs).
set -euo pipefail
dll=$(realpath "$1"); jobfile=$(realpath "$2"); out=$(realpath -m "$3")
here=$(cd "$(dirname "$0")" && pwd); root=$(dirname "$here")
WINE=${WINE:-wine}
JOBS=${JOBS:-$(( $(nproc) / 2 ))}
mkdir -p "$out"

# libd3dcompiler embeds the DLL it is built with, so it is built with this one
[ "$dll" -ef "$root/d3dcompiler_47.dll" ] || cp "$dll" "$root/d3dcompiler_47.dll"
(cd "$root" && cargo build --release -p d3dcompiler >/dev/null)
cc -O2 -o "$out/fxc_driver" "$here/fxc_driver.c" -ldl
x86_64-w64-mingw32-gcc -O2 -o "$out/fxc_driver.exe" "$here/fxc_driver.c"
cp "$dll" "$out/d3dcompiler_47.dll"

winpath() { printf 'Z:%s' "$(printf '%s' "$1" | tr '/' '\\')"; }
# one job file per process and side, every JOBS-th line, so slow shaders spread out
awk -F'|' -v out="$out" -v n="$JOBS" '{ k = (NR - 1) % n
    print $1 "|" $2 "|" $3 "|" $4 "|" out "/" NR ".linux" > (out "/linux-" k ".jobs")
    print $1 "|" $2 "|" $3 "|" $4 "|" out "/" NR ".windows" > (out "/windows-" k ".jobs") }' "$jobfile"
sed -i -E 's#^([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$#Z:\1|\2|\3|\4|Z:\5#; s#/#\\#g' "$out"/windows-*.jobs

for k in $(seq 0 $((JOBS - 1))); do
    [ -s "$out/linux-$k.jobs" ] || continue
    "$out/fxc_driver" "$root/target/release/libd3dcompiler.so" "$out/linux-$k.jobs" >"$out/linux-$k.log" 2>&1 &
    WINEDEBUG=-all "$WINE" "$out/fxc_driver.exe" "$(winpath "$out/d3dcompiler_47.dll")" "$(winpath "$out/windows-$k.jobs")" >"$out/windows-$k.log" 2>&1 &
done
wait

echo "job,source_sha256,entry,target,flags,windows_sha256,linux_sha256,outcome" >"$out/results.csv"
n=0
while IFS='|' read -r src entry target flags; do
    n=$((n + 1))
    w=$out/$n.windows; l=$out/$n.linux
    hw=$([ -f "$w" ] && sha256sum <"$w" | cut -c1-64 || true)
    hl=$([ -f "$l" ] && sha256sum <"$l" | cut -c1-64 || true)
    if [ -z "$hw$hl" ]; then outcome="both failed"
    elif [ -z "$hl" ]; then outcome="only windows compiled"
    elif [ -z "$hw" ]; then outcome="only linux compiled"
    elif [ "$hw" = "$hl" ]; then outcome=identical
    else outcome=different; fi
    echo "$n,$(sha256sum <"$src" | cut -c1-64),$entry,$target,$flags,$hw,$hl,$outcome" >>"$out/results.csv"
done <"$jobfile"
tail -n +2 "$out/results.csv" | cut -d, -f8 | sort | uniq -c
