"""Derive the request/response AES key + IV straight out of the user's own APK.

The App hides them as two byte tables inside `lib/arm64-v8a/libsecurity.so` and
XORs them with two immediates at runtime:

    key(32B) = .rodata[a .. a+32]  XOR KEY_XOR   (default 0x5A)
    iv (16B) = .rodata[b .. b+16]  XOR IV_XOR    (default 0x3B)

Instead of shipping the APK (or the literal bytes) in this repo we brute-scan
`.rodata` for the two windows that decode into printable ASCII and then check
that `iv == key[:16]`, which is a very strong self-check.

usage:  python tools/keyderive.py "/path/to/VPN US ....apk" [--key-xor 0x5A] [--iv-xor 0x3B]
"""
import argparse
import struct
import sys
import zipfile

PRINTABLE = set(range(0x20, 0x7F))


def read_rodata(apk_path: str) -> bytes:
    with zipfile.ZipFile(apk_path) as z:
        so = z.read("lib/arm64-v8a/libsecurity.so")
    e_shoff = struct.unpack_from("<Q", so, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", so, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", so, 0x3C)[0]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        _name, _typ, _flags, _addr, off, size, _l, _i, _a, _e = struct.unpack_from("<IIQQQQIIQQ", so, o)
        # .rodata is the biggest non-exec loadable section with our tables in it
        if 0x2000 < size < 0x20000 and off + size <= len(so):
            blob = so[off:off + size]
            if b"base64Encode" in blob and b"base64Decode" in blob:
                return blob
    raise SystemExit("could not locate .rodata in libsecurity.so")


def scan(blob: bytes, n: int, xor: int):
    hits = []
    for i in range(len(blob) - n):
        cand = bytes(b ^ xor for b in blob[i:i + n])
        if all(b in PRINTABLE for b in cand) and len(set(cand)) >= n // 2:
            hits.append((i, cand))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--key-xor", default="0x5A")
    ap.add_argument("--iv-xor", default="0x3B")
    a = ap.parse_args()
    kx, ix = int(a.key_xor, 0), int(a.iv_xor, 0)
    blob = read_rodata(a.apk)
    print(f".rodata = {len(blob)} bytes")

    keys = scan(blob, 32, kx)
    ivs = {c for _o, c in scan(blob, 16, ix)}
    print(f"32B/XOR {kx:#x} candidates: {len(keys)}   16B/XOR {ix:#x} candidates: {len(ivs)}")

    good = []
    for off, key in keys:
        if key[:16] in ivs:
            good.append((off, key))
            print(f"  MATCH @ +{off:#06x}  key={key.decode()}  iv={key[:16].decode()}")
    if not good:
        print("no key/iv pair found -- pass --key-xor/--iv-xor if the App version changed")
        return 1
    print("\nUse with tools/client.py via env: VPNUS_KEY / VPNUS_IV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
