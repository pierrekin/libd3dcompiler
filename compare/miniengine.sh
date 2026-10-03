#!/usr/bin/env bash
# Writes job files for the shaders of Microsoft's MiniEngine (MIT licence), fetched at a pinned
# commit of DirectX-Graphics-Samples, for compare.sh and compare-dxc.sh:
#
#   miniengine.sh <out dir>    -> <out dir>/miniengine.jobs, <out dir>/miniengine-dxc.jobs
#
# Each shader's stage comes from its file name (…CS.hlsl, …PS.hlsl, …VS.hlsl), as MiniEngine names
# them; every shader's entry point is main. Compiled at optimisation level 3, for shader model 5.0
# with FXC and 6.0 with DXC.
set -euo pipefail
COMMIT=e5975f9b0744
out=$(realpath -m "$1"); src=$out/DirectX-Graphics-Samples
mkdir -p "$out"
if [ ! -d "$src" ]; then
    git clone -q --filter=blob:none --sparse https://github.com/microsoft/DirectX-Graphics-Samples.git "$src"
    git -C "$src" sparse-checkout set MiniEngine/Core/Shaders
fi
git -C "$src" checkout -q "$COMMIT"
for f in "$src"/MiniEngine/Core/Shaders/*.hlsl; do
    case $f in
        *CS.hlsl) t=cs ;;
        *PS.hlsl) t=ps ;;
        *VS.hlsl) t=vs ;;
        *) continue ;;
    esac
    echo "$f|main|${t}_5_0|8000" >&3
    echo "$f|-T|${t}_6_0|-E|main|-O3" >&4
done 3>"$out/miniengine.jobs" 4>"$out/miniengine-dxc.jobs"
wc -l <"$out/miniengine.jobs"
