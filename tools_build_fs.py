#!/usr/bin/env python3
"""
Build a LittleFS image from ./data and optionally flash it.
Falls back to a pure-python packer if mklittlefs is unavailable.
"""
import os, sys, subprocess, struct, argparse

ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA    = os.path.join(ROOT, "data")
OUTDIR  = os.path.join(ROOT, ".build")
OUT     = os.path.join(OUTDIR, "littlefs.bin")
SIZE    = 0x160000        # 1.375 MB  (match your partition table)
BLOCK   = 4096
PAGE    = 256


def find_mklittlefs():
    for cand in ("mklittlefs", "mklittlefs.exe"):
        for p in os.environ.get("PATH", "").split(os.pathsep):
            f = os.path.join(p, cand)
            if os.path.isfile(f):
                return f
    here = os.path.join(ROOT, "tools", "mklittlefs")
    for ext in ("", ".exe"):
        if os.path.isfile(here + ext):
            return here + ext
    return None


def build_with_mklittlefs(binary):
    os.makedirs(OUTDIR, exist_ok=True)
    cmd = [binary, "-c", OUT, "-b", str(BLOCK), "-p", str(PAGE), "-s", str(SIZE), DATA]
    print("[fs] " + " ".join(cmd))
    return subprocess.call(cmd) == 0


def build_simple():
    """Very small packer: writes files sequentially with a manifest header.
    Only used as a fallback so the firmware can still read assets."""
    os.makedirs(OUTDIR, exist_ok=True)
    entries = []
    blob = bytearray()
    for name in sorted(os.listdir(DATA)):
        p = os.path.join(DATA, name)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            data = f.read()
        entries.append((name, len(blob), len(data)))
        blob += data
        blob += b"\x00" * ((PAGE - len(data) % PAGE) % PAGE)

    with open(OUT, "wb") as f:
        f.write(b"LFS1")
        f.write(struct.pack("<I", len(entries)))
        for name, off, ln in entries:
            nb = name.encode()
            f.write(struct.pack("<H", len(nb)))
            f.write(nb)
            f.write(struct.pack("<II", off, ln))
        f.write(blob)
    print(f"[fs] fallback image written: {OUT} ({len(blob)} bytes payload)")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flash", metavar="PORT", help="flash after build")
    a = ap.parse_args()

    if not os.path.isdir(DATA):
        print("[fs] no ./data directory"); return 1

    binary = find_mklittlefs()
    ok = build_with_mklittlefs(binary) if binary else build_simple()
    if not ok:
        print("[fs] mklittlefs failed, using fallback"); ok = build_simple()
    if not ok:
        return 1

    if a.flash:
        cmd = [sys.executable, "-m", "esptool", "--chip", "esp32",
               "--port", a.flash, "--baud", "921600",
               "write_flash", "0x290000", OUT]
        print("[fs] " + " ".join(cmd))
        return subprocess.call(cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())