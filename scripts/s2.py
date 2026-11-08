# _pe_
import sys
p = sys.argv[1]
d = open(p, 'rb').read()
print('tail 64:', d[-64:].hex())
print('tail ascii:', ''.join((chr(c) if 32 <= c < 127 else '.' for c in d[-64:])))
for pat in [b'MSCF', b'MSCF', b'!@#$%^&*', b'SZDD', b"7z\xbc\xaf'\x1c", b'Rar!\x1a\x07', b'PK\x05\x06', b'PK\x01\x02']:
    print(pat, [hex(i) for i in range(len(d)) if d.startswith(pat, i)][:5])
print('--- context at 0x2948e21 ---')
off = 43290145
print(d[off - 256:off + 512])
