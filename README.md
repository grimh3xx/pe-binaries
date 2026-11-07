<img src="docs/banner.svg" alt="PE-Binaries" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/pe-binaries/build.yml?branch=master&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/pe-binaries/actions)
[![license](https://img.shields.io/github/license/grimh3xx/pe-binaries?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![C++17](https://img.shields.io/badge/C%2B%2B-17-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux%20·%20WSL%20·%20Windows-portable-22D3EE?style=flat-square&labelColor=111826)

**An EDR-evasion artifact detector for Windows PE binaries, in portable C++17.** It parses
the PE format by hand — no Windows APIs — so it builds and runs on Linux, WSL and Windows
alike. Where tooling like [Mangle](https://github.com/optiv/Mangle) *forges* the traces
that let a binary slip past an EDR, PE-Binaries sits on the other side of the fence: it
**reads those same traces and flags them**. Strictly read-only — it never writes to the
file it inspects.

<p align="center"><img src="docs/demo.svg" alt="pe-binaries suspect.exe demo" width="100%"></p>

## What it detects

| | |
|---|---|
| **Size inflation** (`BLOAT_OVERLAY`) | A large, low-entropy overlay appended past the last section — padding to exceed an AV's maximum scan size. Severity scales with how much of the file is filler. |
| **Padded section** (`BLOAT_SECTION`) | A section whose raw bytes dwarf its virtual size, with low entropy — bytes that never load into memory. |
| **RWX section** (`RWX_SECTION`) | A section that is both writable and executable — self-modifying code, an unpacking stub or injected shellcode. |
| **Entry-point anomaly** (`EP_OUTSIDE` / `EP_NONEXEC` / `EP_WRITABLE`) | Execution starts outside every section, in a non-executable section, or in a writable one — packer/loader tricks. |
| **Suspicious imports** (`SUSPICIOUS_IMPORTS`) | Injection, anti-debug, token-manipulation and hooking APIs, grouped and weighted. A lone helper is weak; a real injection combo is `HIGH`. |
| **Hidden imports** (`DYNAMIC_RESOLUTION` / `FEW_IMPORTS`) | `GetProcAddress` + `LoadLibrary` with a thin import table, or almost no imports behind real code — the import table is being hidden. |
| **TLS callback** (`TLS_CALLBACK`) | Code that runs before the entry point — early init, but also anti-debug and stealth execution. |
| **Stripped Go build ID** (`GO_BUILDID_STRIPPED`) | Go runtime markers present but the build ID removed — a known signature-evasion step. |
| **Signature & checksum** (`UNSIGNED` / `CHECKSUM_INVALID`) | No Authenticode certificate table, or a signed file whose header checksum no longer matches — i.e. modified after signing. |
| **Timestamp forgery** (`TS_ZERO` / `TS_FUTURE`) | Zeroed or future `TimeDateStamp` — erased or tampered build provenance. |
| **Packing** (`HIGH_ENTROPY` / `PACKER_SECTION` / `ABNORMAL_SECTION`) | High-entropy sections, known packer section layouts, or non-standard section names. |

Findings are ranked worst-first, tagged `INFO` / `LOW` / `MEDIUM` / `HIGH`, and rolled up
into a **0–100 risk score** (`CLEAN` → `HIGH RISK`). Every check reads the file; none modify it.

## IOCs

For triage and threat-intel pivots, every report includes **SHA-256**, **MD5** and a
pefile-compatible **imphash** (import hash) — the same value VirusTotal and most sandboxes
use to cluster related samples — plus the import table (functions per DLL).

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

No dependencies beyond a C++17 compiler and CMake. Builds with GCC, Clang and MSVC.

## Usage

```text
pe-binaries [options] <file.exe|file.dll> [more files...]

  -q, --quiet     only print findings, skip the image summary
  -s, --strict    exit non-zero if any MEDIUM or HIGH finding is present
      --json      emit a JSON report instead of text
      --color     force ANSI color (default: auto when stdout is a TTY)
      --no-color  disable ANSI color
  -h, --help      show this help
```

`--strict` makes it usable as a CI / pipeline gate: a MEDIUM or HIGH finding fails the run.
`--json` emits a machine-readable report (hashes, imphash, risk score, findings) for pipelines.

```bash
pe-binaries suspect.exe                       # full report
pe-binaries -q -s build/*.exe                 # gate a build directory
pe-binaries --json sample.dll | jq .risk_score
```

## How it reads a PE

| Stage | What it looks at |
|---|---|
| Headers | DOS + NT signatures, machine, `TimeDateStamp`, PE32/PE32+ |
| Sections | raw vs virtual size, per-section Shannon entropy, executable flag |
| Overlay | bytes past the last section's raw data and the certificate table |
| Security dir | presence and size of the Authenticode certificate table |
| Go markers | `.gopclntab` / `.go.buildinfo` sections and build-ID strings |

## Scope & intent

PE-Binaries is a **defensive / analysis** tool for malware triage, threat intel and
build-pipeline hygiene. It reports the *presence* of artifacts; it does not validate
certificate chains, and it does not modify binaries. It exists to **recognise** tampering,
not to perform it.

## Development

```bash
python3 tests/test.py build/pe-binaries   # functional tests (synthetic PE fixtures)
python3 tools/gen_demo.py                 # regenerate docs/demo.svg (animated terminal)
```

CI builds on Linux and Windows and runs the test suite on every push.

The banner and demo SVGs are generated art (JBM font embedded); they match the rest of the
[grimh3xx](https://github.com/grimh3xx) profile.

## License

MIT
