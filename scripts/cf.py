# _pe_
import sys, struct as st2
p = sys.argv[1]
d = open(p, 'rb').read()

def prs_cfb(buf, base=0):
    if buf[base:base + 8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        print('  not CFB at', hex(base))
        return
    hdr = buf[base:base + 512]
    sig, cls2, min3, maj, bom, ssh, msh, _, ndir, nfat, dir3, _, cut, min_sta, nmi, dif_sta, ndi = st2.unpack_from('<8s16sHHHHHH6I', hdr, 0)
    print('  CLSID', cls2.hex(), 'minor', min3, 'major', maj, 'sshift', ssh, 'dirsectors', ndir, 'fatsec', nfat, 'dir1st', dir3)
    sec3 = 1 << ssh

    def sec(n):
        return buf[base + (n + 1) * sec3:base + (n + 2) * sec3]
    fat = []
    for i in range(nfat):
        fat += list(st2.unpack_from('<%dI' % (sec3 // 4), sec(i)))

    def cha(sta2):
        out = []
        cur = sta2
        while cur < 4294967290 and len(out) < 10000:
            out.append(cur)
            if cur >= len(fat):
                break
            cur = fat[cur]
        return out
    dirt = b''.join((sec(s) for s in cha(dir3)))
    ents = []
    for i in range(len(dirt) // 128):
        e = dirt[i * 128:(i + 1) * 128]
        nam2 = st2.unpack_from('<H', e, 64)[0]
        if nam2 < 2:
            continue
        name = e[:nam2 - 2].decode('utf-16-le', 'replace')
        ety = e[66]
        sta2 = st2.unpack_from('<I', e, 116)[0]
        size = st2.unpack_from('<Q', e, 120)[0] & 4294967295
        ents.append((name, ety, sta2, size))
    for name, ety, sta2, size in ents:
        print('   ', 'DIR ' if ety == 5 else 'FILE', name, 'start', sta2, 'size', size)
for sig in [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1']:
    idx = d.find(sig)
    print('CFB sig at', hex(idx) if idx >= 0 else None)
    if idx >= 0:
        prs_cfb(d, idx)
i = d.find(b'PK\x05\x06')
while i >= 0:
    print('EOCD at', hex(i), d[i:i + 22].hex())
    i = d.find(b'PK\x05\x06', i + 1)
    if i > 50331648:
        break
