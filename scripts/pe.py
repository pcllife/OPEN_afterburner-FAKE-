# _pe_
import sys, pefile as pef, capstone as cap, struct as st2, os

def hex2(b, base=0, n=None):
    if n:
        b = b[:n]
    for i in range(0, len(b), 16):
        chu = b[i:i + 16]
        h = ' '.join((f'{c:02x}' for c in chu))
        a = ''.join((chr(c) if 32 <= c < 127 else '.' for c in chu))
        print(f'{base + i:08X}  {h:<47}  {a}')

def main(path):
    pe = pef.PE(path, fast_load=False)
    print('FILE', path, os.path.getsize(path))
    print('Machine %04X' % pe.FILE_HEADER.Machine, 'TimeDateStamp', pe.FILE_HEADER.TimeDateStamp, 'Subsystem', pe.OPTIONAL_HEADER.Subsystem, 'DllChar', hex(pe.OPTIONAL_HEADER.DllCharacteristics), 'ImageBase', hex(pe.OPTIONAL_HEADER.ImageBase), 'Entry', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    for s in pe.sections:
        print('SEC %-9s VA=%08X VS=%08X RAW=%08X RS=%08X ch=%08X' % (s.Name.rstrip(b'\x00').decode(errors='replace'), s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData, s.Characteristics))
    for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        print('IMPORT', e.dll.decode())
        for imp in e.imports:
            if imp.name:
                print('   ', hex(imp.address), imp.name.decode())
            else:
                print('   ', hex(imp.address), 'ord', imp.ordinal)
    for e in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []:
        pass
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print('EXPORTS', pe.DIRECTORY_ENTRY_EXPORT.name)
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print('   ', hex(s.address), s.name)
if __name__ == '__main__':
    main(sys.argv[1])
