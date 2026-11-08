# _pe_
import sys, struct as st2
p = sys.argv[1]
d = open(p, 'rb').read()
mag = b'NullsoftInst'
i = d.find(mag)
hs = i - 28
print('header_start', hex(hs))
fla, sig3 = st2.unpack_from('<II', d, hs)
nin = st2.unpack_from('<III', d, hs + 8)
loh, loa = st2.unpack_from('<II', d, hs + 20)
print('flags=%08X siginfo=%08X nsinst=%s len_header=%d len_all=%d' % (fla, sig3, nin, loh, loa))
off = hs + loh
print('data starts', hex(off))
blk = hs
nam3 = {1: 'COMMON', 2: 'PAGE', 3: 'SECTION', 4: 'ENTRY', 5: 'FILE', 6: 'UNINST'}
end = hs + loh
while blk < end - 8:
    size, typ = st2.unpack_from('<II', d, blk)
    if size == 0 or size > loh:
        print('stopping at', hex(blk), size, typ)
        break
    print('block @%08X size=%d type=%d(%s)' % (blk, size, typ, nam3.get(typ, '?')))
    if typ == 5:
        fie = blk + 8
        o_low, sz_low, t_low, t_high = st2.unpack_from('<IIII', d, fie)
        f = fie + 16
        o_high, sz_high = st2.unpack_from('<II', d, f)
        f2 = f + 8
        nlen = st2.unpack_from('<H', d, f2)[0]
        name = d[f2 + 2:f2 + 2 + nlen]
        print('    file off=%d size_low=%d time=%08X%08X' % (o_low, sz_low, t_high, t_low))
        print('    tryNSIS3 o_high=%d sz_high=%d namelen=%d name=%r' % (o_high, sz_high, nlen, name))
        nlen_2 = st2.unpack_from('<H', d, f)[0]
        print('    alt2 namelen=%d %r' % (nlen_2, d[f + 2:f + 2 + nlen_2]))
    blk += size
