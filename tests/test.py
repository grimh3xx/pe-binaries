#!/usr/bin/env python3
"""Functional tests for pe-binaries.

Builds minimal synthetic PE32+ fixtures in a temp dir and asserts that the
tool parses them and raises (or does not raise) the expected findings. No real
binaries are committed; everything is generated here.

Usage: python3 tests/test.py [path-to-pe-binaries]   (default: build/pe-binaries)
"""
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

BIN = sys.argv[1] if len(sys.argv) > 1 else "build/pe-binaries"

SEC_EXEC = 0x20000000
SEC_WRITE = 0x80000000
SEC_READ = 0x40000000
SEC_CODE = 0x00000020


def build_pe(sections, overlay=b"", entry_in=0):
    """sections: list of (name, characteristics, raw_bytes). entry_in: section idx."""
    file_align, sec_align = 0x200, 0x1000
    n = len(sections)
    opt_size = 240  # PE32+ with 16 data directories

    headers_size = 0x80 + 4 + 20 + opt_size + n * 40
    headers_size = (headers_size + file_align - 1) // file_align * file_align

    # lay sections out
    laid, raw_ptr, va = [], headers_size, sec_align
    for name, ch, data in sections:
        raw = len(data)
        raw_al = (raw + file_align - 1) // file_align * file_align
        laid.append((name, ch, data, va, raw, raw_ptr, raw_al))
        raw_ptr += raw_al
        va += (max(raw, 1) + sec_align - 1) // sec_align * sec_align
    size_of_image = (va + sec_align - 1) // sec_align * sec_align
    entry_rva = laid[entry_in][3] if laid else 0

    # DOS header
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    # file header
    fh = struct.pack("<HHIIIHH", 0x8664, n, 0, 0, 0, opt_size, 0x22)

    # optional header (PE32+), fields at the offsets pe.cpp reads
    oh = bytearray(opt_size)
    struct.pack_into("<H", oh, 0, 0x20b)              # Magic
    struct.pack_into("<I", oh, 16, entry_rva)         # AddressOfEntryPoint
    struct.pack_into("<Q", oh, 24, 0x140000000)       # ImageBase
    struct.pack_into("<I", oh, 56, size_of_image)     # SizeOfImage
    struct.pack_into("<I", oh, 60, headers_size)      # SizeOfHeaders
    struct.pack_into("<I", oh, 64, 0)                 # CheckSum
    struct.pack_into("<I", oh, 108, 16)               # NumberOfRvaAndSizes

    # section table
    st = bytearray()
    for name, ch, data, sva, raw, rptr, _ in laid:
        nm = name.encode()[:8].ljust(8, b"\0")
        st += nm + struct.pack("<IIIIIIHHI", len(data), sva, raw, rptr, 0, 0, 0, 0, ch)

    out = bytearray()
    out += dos + b"PE\0\0" + fh + oh + st
    out = out.ljust(headers_size, b"\0")
    for name, ch, data, sva, raw, rptr, raw_al in laid:
        out = out.ljust(rptr, b"\0") + data
        out = out.ljust(rptr + raw_al, b"\0")
    out += overlay
    return bytes(out)


def run(path, *args):
    r = subprocess.run([BIN, "--json", *args, str(path)],
                       capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout)


PASS, FAIL = 0, 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  \033[32mok\033[0m   {name}")
    else:
        FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name}")


def ids(doc):
    return {f["id"] for f in doc["findings"]}


def main():
    tmp = Path(tempfile.mkdtemp())
    code = b"\xc3" * 0x400  # ret padding — plausible .text

    # 1. clean-ish binary
    clean = tmp / "clean.exe"
    clean.write_bytes(build_pe([(".text", SEC_EXEC | SEC_READ | SEC_CODE, code),
                                (".rdata", SEC_READ, b"hello" * 64)]))
    rc, d = run(clean)
    check("clean: parses as PE32+ x64", d["type"] == "PE32+ x64 EXE")
    check("clean: sha256 is 64 hex", len(d["sha256"]) == 64)
    check("clean: no RWX finding", "RWX_SECTION" not in ids(d))

    # 2. RWX section -> HIGH
    rwx = tmp / "rwx.exe"
    rwx.write_bytes(build_pe([(".text", SEC_EXEC | SEC_WRITE | SEC_READ | SEC_CODE, code)]))
    rc, d = run(rwx)
    check("rwx: RWX_SECTION raised", "RWX_SECTION" in ids(d))
    check("rwx: risk > 0", d["risk_score"] > 0)

    # 3. bloated overlay -> BLOAT_OVERLAY + strict exit 1
    bloat = tmp / "bloat.exe"
    bloat.write_bytes(build_pe([(".text", SEC_EXEC | SEC_READ | SEC_CODE, code)],
                               overlay=b"\x00" * (8 << 20)))
    rc, d = run(bloat, "-s")
    check("bloat: BLOAT_OVERLAY raised", "BLOAT_OVERLAY" in ids(d))
    check("bloat: --strict exits non-zero", rc == 1)

    # 4. abnormal section name
    odd = tmp / "odd.exe"
    odd.write_bytes(build_pe([(".text", SEC_EXEC | SEC_READ | SEC_CODE, code),
                              ("hackz", SEC_READ, b"x" * 64)]))
    rc, d = run(odd)
    check("odd: ABNORMAL_SECTION raised", "ABNORMAL_SECTION" in ids(d))

    # 5. non-PE input is rejected cleanly
    junk = tmp / "junk.bin"
    junk.write_bytes(b"not a pe at all")
    r = subprocess.run([BIN, "--json", str(junk)], capture_output=True, text=True)
    check("junk: rejected (exit 2)", r.returncode == 2)

    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
