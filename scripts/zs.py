# _pe_
import sys, zipfile as zip2, io
p = sys.argv[1]
d = open(p, 'rb').read()
for off in [900307, 43340070]:
    print('=== zip at', hex(off))
    try:
        bio = io.BytesIO(d[off:])
        z = zip2.ZipFile(bio)
        for i in z.infolist()[:40]:
            print('   ', i.filename, i.file_size)
        print('   total', len(z.infolist()))
    except Exception as e:
        print('   fail', e)
