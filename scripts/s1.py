# _pe_
import re, sys
p = sys.argv[1]
d = open(p, 'rb').read()
for pat in [b'Inno Setup', b'Nullsoft', b'InstallShield', b'7-Zip', b'Rar!', b'PK\x03\x04', b'MSCF', b'MSI Afterburner', b'RTCore', b'NT\\.\\RTCore']:
    offs = [m.start() for m in re.finditer(re.escape(pat), d)][:5]
    print(pat, len(offs), [hex(o) for o in offs])
print('size', len(d))
