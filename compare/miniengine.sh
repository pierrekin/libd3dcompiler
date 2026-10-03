#!/usr/bin/env bash
# Writes a job file for the shaders of Microsoft's MiniEngine (MIT licence), fetched at a pinned
# commit of DirectX-Graphics-Samples, for compare.sh:
#
#   miniengine.sh <out dir>    -> <out dir>/miniengine.jobs
#
# Each shader's stage comes from its file name (…CS.hlsl, …PS.hlsl, …VS.hlsl), as MiniEngine names
# them; every shader's entry point is main. Compiled for shader model 5.0 at optimisation level 3.
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
        *CS.hlsl) t=cs_5_0 ;;
        *PS.hlsl) t=ps_5_0 ;;
        *VS.hlsl) t=vs_5_0 ;;
        *) continue ;;
    esac
    echo "$f|main|$t|8000"
done >"$out/miniengine.jobs"
wc -l <"$out/miniengine.jobs"
