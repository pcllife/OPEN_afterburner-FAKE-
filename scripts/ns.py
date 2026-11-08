# _pe_
import sys, struct as st2
p = sys.argv[1]
d = open(p, 'rb').read()
print('last 8:', d[-8:].hex(), st2.unpack('<I', d[-4:])[0], hex(st2.unpack('<I', d[-4:])[0]))
pat = b'\xef\xbe\xad\xde'
i = d.find(pat)
while i >= 0:
    print('BEEF at', hex(i), d[i:i + 32])
    i = d.find(pat, i + 1)
