# Comparison results

Each file is one run of `compare/compare.sh`: every shader compiled with `D3DCompile` on Linux,
through this library, and on Windows under Wine, with the bytecode compared. One row per shader:
the source's SHA-256, the entry point, target and `Flags1` it was compiled with, the SHA-256 of each
side's output, and the outcome. `both failed` means the shader does not compile on either side.

Both runs were made on 2026-10-03 with:

- `d3dcompiler_47.dll` version 10.0.19041.1 (WinBuild.160101.0800), the copy Unreal Engine 5 ships:
  SHA-1 `0addaa4d0bd4395bfc02d3025decc23b1b22340c`, SHA-256
  `e93f3c4bcc6dbaffa91d739ac4a941edbc616e00ae18b19e480ca2d382986c56`.
- This library at `727424d`.
- On the Windows side, Wine 11.0 from Proton 11.0 (`proton-11.0-2c`). The DLL runs there on Wine's
  own C runtime (`ucrtbase`), not Microsoft's, so "Windows" here means the same DLL on Wine's runtime.

| File | Shaders | Identical | Both failed | Different |
| --- | --- | --- | --- | --- |
| `unreal-5.8-sm5.csv` | 5744 | 5603 | 141 | 0 |
| `miniengine.csv` | 150 | 77 | 73 | 0 |

`unreal-5.8-sm5.csv` covers the SM5 shaders of an Unreal Engine 5.8.3 cook for Windows: the engine's
global shaders and a project's materials, with each job's source and `Flags1` as the engine's
shader debug dumps record them. The sources are Unreal Engine's and are not included; only their
hashes are. The same shaders also came out byte-identical to a cook on real Windows.

`miniengine.csv` covers Microsoft's MiniEngine shaders, fetched by `compare/miniengine.sh`, and can
be reproduced from this repository. The shaders that fail on both sides use HLSL 2021 features,
such as `select`, that FXC does not support.
