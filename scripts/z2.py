# _pe_
import sys, struct as st2
p = sys.argv[1]
d = open(p, 'rb').read()
for off in [42439664, 43339971, 45583837]:
    print('---', hex(off), d[off:off + 48])
i = 0
cnt = 0
while True:
    i = d.find(b'PK\x03\x04', i)
    if i < 0:
        break
    cnt += 1
    if cnt < 10:
        print('LFH at', hex(i))
    i += 1
print('total LFH', cnt)
e = d[43340043:43340043 + 22]
print('EOCD', e.hex())
n = st2.unpack_from('<H', e, 10)[0]
cdsz = st2.unpack_from('<I', e, 12)[0]
cdo = st2.unpack_from('<I', e, 16)[0]
print('entries', n, 'cdsize', hex(cdsz), 'cdoff', hex(cdo), 'filesize', hex(len(d)))
print('at cdoff', d[cdo:cdo + 80])
