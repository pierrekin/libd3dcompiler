# Comparison results

Each file is one run of `compare/compare.sh` (FXC) or `compare/compare-dxc.sh` (DXC): every shader
compiled on Linux, through this library, and on Windows under Wine, with the output compared. One
row per shader: the source's SHA-256, what it was compiled with, the SHA-256 of each side's output,
and the outcome. `both failed` means the shader does not compile on either side.

The FXC runs were made on 2026-10-03 with:

- `d3dcompiler_47.dll` version 10.0.19041.1 (WinBuild.160101.0800), the copy Unreal Engine 5 ships:
  SHA-1 `0addaa4d0bd4395bfc02d3025decc23b1b22340c`, SHA-256
  `e93f3c4bcc6dbaffa91d739ac4a941edbc616e00ae18b19e480ca2d382986c56`.
- This library at `727424d`.
- On the Windows side, Wine 11.0 from Proton 11.0 (`proton-11.0-2c`). The DLL runs there on Wine's
  own C runtime (`ucrtbase`), not Microsoft's, so "Windows" here means the same DLL on Wine's runtime.

The DXC run was made on 2026-10-03 with this library at `cdf3e89`, Wine as above, and:

- DXC 1.8 as Unreal Engine 5.8 ships it, `dxcompiler.dll` SHA-1
  `3406d9851acbbd46b506f352c2c73a0def183313`, and `dxil.dll` 101.8.2403.18, SHA-1
  `84ea97d5f87671009c29242fde768f98f85a5664`, which signs the output on both sides.
- Microsoft's C++ runtime 14.40.33810.0 on both sides (Wine told to use it rather than its own):
  `MSVCP140.dll` SHA-1 `8e6a0257591eb913ae7d0e975c56306b3f680b3f`, `VCRUNTIME140.dll`
  `4812da5eb86a93fb0adc5bb60a4980ee8b0ad33a`, `VCRUNTIME140_1.dll`
  `dfa7a46012483837f47d8c870973a2dea786d9ff`.

| File | Compiler | Shaders | Identical | Both failed | Different |
| --- | --- | --- | --- | --- | --- |
| `unreal-5.8-sm5.csv` | FXC | 5744 | 5603 | 141 | 0 |
| `miniengine.csv` | FXC | 150 | 77 | 73 | 0 |
| `miniengine-dxc.csv` | DXC | 150 | 150 | 0 | 0 |

`unreal-5.8-sm5.csv` covers the SM5 shaders of an Unreal Engine 5.8.3 cook for Windows: the engine's
global shaders and a project's materials, with each job's source and `Flags1` as the engine's
shader debug dumps record them. The sources are Unreal Engine's and are not included; only their
hashes are. The same shaders also came out byte-identical to a cook on real Windows.

`miniengine.csv` and `miniengine-dxc.csv` cover Microsoft's MiniEngine shaders, fetched by
`compare/miniengine.sh`, and can be reproduced from this repository: with FXC for shader model 5.0,
and with DXC for 6.0. The shaders that fail with FXC use HLSL 2021 features, such as `select`, that
FXC does not support.
