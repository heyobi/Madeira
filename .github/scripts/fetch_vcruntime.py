#!/usr/bin/env python3
"""Extract the twelve x64 VC++ runtime DLLs (tools/fetch-vcruntime.md) from VC_redist.x64.exe.

The redistributable is a bundle of MSIs whose cabinets name their members by MSI file key
(e.g. F_CENTRAL_msvcp140_x64), not by DLL name. So everything is unpacked recursively with
7-Zip and each x64 PE is identified by the OriginalFilename in its version resource.

usage: fetch_vcruntime.py VC_redist.x64.exe DEST_DIR
Exits non-zero unless all twelve DLLs were found. Files are copied byte for byte.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

WANT = {n + ".dll" for n in (
    "concrt140 msvcp140 msvcp140_1 msvcp140_2 msvcp140_atomic_wait msvcp140_codecvt_ids "
    "vcamp140 vccorlib140 vcomp140 vcruntime140 vcruntime140_1 vcruntime140_threads").split()}
KEY = "OriginalFilename".encode("utf-16-le")


def unpack(path, out):
    return subprocess.run(["7zz", "x", "-y", path, "-o" + out],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def original_filename(data):
    """OriginalFilename of an x64 PE image, lower-cased, or None."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", data, pe + 4)[0] != 0x8664:
        return None
    i = data.find(KEY)
    if i < 0:
        return None
    m = re.match(rb"(?:\x00\x00)*((?:[^\x00]\x00)+)", data[i + len(KEY):])
    return m.group(1).decode("utf-16-le").strip().lower() if m else None


def main(exe, dest):
    work = tempfile.mkdtemp(prefix="vcredist-")
    pending = [(exe, os.path.join(work, "0"))]
    for _ in range(4):  # bundle -> embedded MSI/cab -> cab -> files
        nxt = []
        for src, out in pending:
            if not unpack(src, out):
                continue
            for root, _, files in os.walk(out):
                for f in files:
                    p = os.path.join(root, f)
                    nxt.append((p, p + ".x"))
        pending = nxt

    found = {}
    for root, _, files in os.walk(work):
        for f in files:
            p = os.path.join(root, f)
            try:
                with open(p, "rb") as fh:
                    name = original_filename(fh.read())
            except OSError:
                continue
            if name in WANT and name not in found:
                found[name] = p

    os.makedirs(dest, exist_ok=True)
    for name, p in sorted(found.items()):
        shutil.copyfile(p, os.path.join(dest, name))
        print(f"  {name} <- {os.path.relpath(p, work)}")
    missing = sorted(WANT - found.keys())
    print(f"VC++ runtime DLLs bundled: {len(found)} of {len(WANT)}")
    if missing:
        print("missing: " + " ".join(missing))
        for root, _, files in os.walk(work):
            for f in files[:40]:
                print("   ", os.path.relpath(os.path.join(root, f), work))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
