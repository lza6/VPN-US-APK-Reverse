"""Resolve .rodata references inside the two JNI entry points of libsecurity.so.

usage:  python tools/dis_refs.py [libsecurity.so]

Extract the .so first:  unzip -j "<apk>" 'lib/arm64-v8a/libsecurity.so' -d .
(pip install capstone)
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

d = open(sys.argv[1] if len(sys.argv) > 1 else 'libsecurity.so', 'rb').read()

def sections(d):
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', d, o)
        secs.append(dict(name=name, typ=typ, addr=addr, off=off, size=size))
    st = secs[e_shstrndx]
    for s in secs:
        s['sname'] = d[st['off'] + s['name']:d.index(b'\x00', st['off'] + s['name'])].decode()
    return secs

secs = sections(d)

def va2off(va):
    for s in secs:
        if s['addr'] and s['addr'] <= va < s['addr'] + s['size'] and s['typ'] != 8:
            return s['off'] + (va - s['addr'])
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for name, va, size in [('encryptAes', 0x1a7f0, 924), ('decryptAes', 0x1ac28, 1216)]:
    print('=' * 40, name)
    off = va2off(va)
    code = d[off:off + size]
    page = None
    buf = {}
    for ins in md.disasm(code, va):
        if ins.mnemonic == 'adrp' and len(ins.operands) == 2:
            try:
                page = ins.operands[1].imm
            except Exception:
                page = None
            rd = ins.reg_name(ins.operands[0].reg)
            buf[rd] = page
        elif ins.mnemonic == 'add' and len(ins.operands) == 3:
            rd = ins.reg_name(ins.operands[0].reg)
            rn = ins.reg_name(ins.operands[1].reg)
            if rn in buf:
                try:
                    imm = ins.operands[2].imm
                except Exception:
                    continue
                tgt = buf[rn] + imm
                o = va2off(tgt)
                if o is None:
                    continue
                data = d[o:o + 48]
                print(f'{ins.address:#x}: ADDR {tgt:#x} -> {data!r}')
