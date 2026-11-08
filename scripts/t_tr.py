# _test_
import json
from pathlib import Path
import unittest as uni2
from tr import call_edg, dec_ctl_code, dsp_cas, ioc_lit, prs_json_str

class TrTes(uni2.TestCase):

    def test_con_jso_str(self):
        self.assertEqual(prs_json_str(' {"one":1}\n{"two":2} '), [{'one': 1}, {'two': 2}])
        self.assertEqual(prs_json_str('  '), [])

    def test_ctl_cod_bit(self):
        self.assertEqual(dec_ctl_code(2147491888), {'device_type': '0x8000', 'access': 0, 'function': '0x80c', 'method': 0})

    def test_lit_wra_arg(self):
        ope2 = ['0', 'eax', '0xc', 'dword [ebp + 8]', '0xc', 'dword [ebp + 8]', '0x80002030', 'dword [ecx + 4]']
        ops = [{'offset': 4096 + i, 'type': 'push', 'disasm': 'push ' + ope} for i, ope in enumerate(ope2)]
        ops.append({'offset': 4112, 'type': 'ucall', 'disasm': 'call dword [0x2000]'})
        edge = {'site_rva': '0x10', 'resolution': 'iat', 'target': 'KERNEL32.dll!DeviceIoControl'}
        res4 = ioc_lit({'ops': ops}, [edge], 4096)
        self.assertEqual(res4[0]['code'], '0x80002030')
        self.assertEqual(res4[0]['input_length_literal'], 12)
        self.assertEqual(res4[0]['output_length_literal'], 12)

    def test_bra_pre_cro_pat_sta_gue(self):
        ops = [{'offset': i, 'type': 'push', 'disasm': 'push 0x80002030'} for i in range(8)]
        ops += [{'offset': 8, 'type': 'cjmp', 'disasm': 'je 12'}, {'offset': 9, 'type': 'ucall', 'disasm': 'call eax'}]
        edge = {'site_rva': '0x9', 'resolution': 'iat', 'target': 'KERNEL32.dll!DeviceIoControl'}
        self.assertEqual(ioc_lit({'ops': ops}, [edge], 0), [])

    def test_equ_and_ine_dis_cas(self):
        ops = [{'offset': 16, 'disasm': 'mov r8d, 0x8000202c', 'size': 6}, {'offset': 22, 'disasm': 'cmp eax, r8d', 'size': 3}, {'offset': 25, 'disasm': 'ja 0x80', 'jump': 128, 'size': 2}, {'offset': 27, 'disasm': 'cmp eax, r8d', 'size': 3}, {'offset': 30, 'disasm': 'je 0x90', 'jump': 144, 'size': 2}, {'offset': 32, 'disasm': 'cmp eax, 0x80002028', 'size': 5}, {'offset': 37, 'disasm': 'jne 0xa0', 'jump': 160, 'fail': 39, 'size': 2}]
        res4 = dsp_cas({'ops': ops}, 0)
        self.assertEqual([(x['code'], x['handler_rva']) for x in res4], [('0x8000202c', '0x90'), ('0x80002028', '0x27')])

    def test_dir_imp_and_ind_res_are_dis(self):
        mod3 = {'image_base': '0x1000', 'exports': [{'name': '?Method@Example@@', 'rva': '0x20'}], 'imports': [{'iat_va': '0x2000', 'dll': 'KERNEL32.dll', 'name': 'Example', 'ordinal': None}]}
        fn = {'ops': [{'offset': 4096, 'type': 'call', 'jump': 4128, 'disasm': 'call 0x1020'}, {'offset': 4101, 'type': 'ucall', 'ptr': 8192, 'disasm': 'call dword [0x2000]'}, {'offset': 4107, 'type': 'ucall', 'disasm': 'call eax'}]}
        self.assertEqual([edge['resolution'] for edge in call_edg(fn, mod3)], ['export', 'iat', 'unresolved_indirect'])

    def test_rec_wra_cat_con(self):
        path = Path(__file__).resolve().parents[1] / 'analysis' / 'phase2' / 'callgraph.json'
        if not path.is_file():
            self.skipTest('No local trace artifacts')
        rpt = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(len(rpt['ioctl_wrappers']), 14)
        for ent in rpt['ioctl_wrappers']:
            self.assertIsNotNone(ent['kernel_handler_rva'])
            self.assertEqual(ent['input_length_literal'], ent['output_length_literal'])
        tbl = {(ent['vtable'], ent['slot_offset']): ent for ent in rpt['vtable_slots']}
        ent = tbl['??_7CHALImplementationNVAPI@@6B@', '0x18c']
        self.assertEqual(ent['target_rva'], '0x63f30')
        self.assertIn('SetClockBoost', ent['target_export'])
if __name__ == '__main__':
    uni2.main()
