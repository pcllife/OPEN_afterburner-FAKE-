# _test_
import unittest as uni2
import subprocess as sub2
import sys
import tempfile as tem
from pathlib import Path
from types import SimpleNamespace as sim_nam
from inv import dec, dri_ass, imp3, str_evi, ver6

class FakePe:

    def get_rva_from_offset(self, off2):
        return off2 + 4096

class InvTes(uni2.TestCase):

    def test_dec_non_and_inv_utf(self):
        self.assertIsNone(dec(None))
        self.assertEqual(dec(b'RTCore64.sys'), 'RTCore64.sys')
        self.assertEqual(dec(b'\xff'), '�')

    def test_str_off_and_enc(self):
        asc_name = b'MAHMSharedMemory'
        uni_name = 'D3DKMTQueryStatistics'.encode('utf-16-le')
        data = b'\x01\x02' + asc_name + b'\x00\x01\x02' + uni_name + b'\x00\x00'
        res4 = str_evi(data, FakePe())
        by_name = {ent['text']: ent for ent in res4}
        self.assertEqual(by_name['MAHMSharedMemory']['file_offset'], '0x2')
        self.assertEqual(by_name['MAHMSharedMemory']['rva'], '0x1002')
        self.assertEqual(by_name['D3DKMTQueryStatistics']['encoding'], 'utf-16-le')
        self.assertEqual(int(by_name['D3DKMTQueryStatistics']['file_offset'], 16), 2 + len(asc_name) + 3)

    def test_unr_str_are_not_inc(self):
        self.assertEqual(str_evi(b'Hello world!\x00An unrelated label', FakePe()), [])

    def test_nor_and_del_imp(self):
        sym3 = sim_nam(name=b'DeviceIoControl', ordinal=None, address=4096)
        del2 = sim_nam(name=None, ordinal=12, address=8192)
        pe = sim_nam(DIRECTORY_ENTRY_IMPORT=[sim_nam(dll=b'KERNEL32.dll', imports=[sym3])], DIRECTORY_ENTRY_DELAY_IMPORT=[sim_nam(dll=b'OTHER.dll', imports=[del2])])
        res4 = imp3(pe)
        self.assertEqual([ent['kind'] for ent in res4], ['normal', 'delay'])
        self.assertEqual(res4[1]['ordinal'], 12)
        self.assertIsNone(res4[1]['name'])

    def test_no_ver_res(self):
        self.assertEqual(ver6(sim_nam()), {})

    def test_out_ins_sam_is_rej(self):
        scr = Path(__file__).with_name('inv.py')
        with tem.TemporaryDirectory() as tmp:
            smp = Path(tmp) / 'sample'
            smp.mkdir()
            out2 = smp / 'reports'
            res4 = sub2.run([sys.executable, str(scr), '--base', str(smp), '--out', str(out2)], capture_output=True, text=True)
            self.assertEqual(res4.returncode, 2)
            self.assertIn('outside the sample directory', res4.stderr)
            self.assertFalse(out2.exists())

    def test_dri_rip_rel_imp_ann(self):
        code = b'\xff\x15\x00\x00\x00\x00\x0f2\xc3'
        sec4 = sim_nam(Characteristics=536870912, Name=b'.text\x00\x00\x00', Misc_VirtualSize=len(code), SizeOfRawData=len(code), VirtualAddress=4096, get_data=lambda: code)
        pe = sim_nam(FILE_HEADER=sim_nam(Machine=34404), OPTIONAL_HEADER=sim_nam(ImageBase=0, AddressOfEntryPoint=4096), sections=[sec4])
        ass, can = dri_ass(pe, [{'iat_va': '0x1006', 'dll': 'ntoskrnl.exe', 'name': 'Example', 'ordinal': None}])
        self.assertIn('ntoskrnl.exe!Example', ass)
        self.assertEqual(can[0]['mnemonic'], 'rdmsr')
        self.assertEqual(can[0]['rva'], '0x1006')
if __name__ == '__main__':
    uni2.main()
