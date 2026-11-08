# _test_
import json
from pathlib import Path
import struct as st2
from types import SimpleNamespace as sim_nam
import unittest as uni2
from vx import prs_tbl
root2 = Path(__file__).resolve().parents[1]
pha = root2 / 'analysis' / 'phase7'
BASE = 6442450944

class SynPe:

    def __init__(self, data, raw_size=None, exe2=True, tbl_sec=True):
        self.OPTIONAL_HEADER = sim_nam(ImageBase=BASE)
        self.data = data
        self.table = sim_nam(VirtualAddress=8192, SizeOfRawData=len(data) if raw_size is None else raw_size)
        self.code = sim_nam(Characteristics=536870912 if exe2 else 0)
        self.table_section = tbl_sec

    def get_section_by_rva(self, rva):
        if rva == 8192:
            return self.table if self.table_section else None
        if 4096 <= rva < 6144:
            return self.code
        return None

    def get_data(self, rva, size):
        off2 = rva - 8192
        return self.data[off2:off2 + size]

def rec(tgt=4096, sel2=256749163, res=0):
    return st2.pack('<QII', BASE + tgt, sel2, res)

class DspTblTes(uni2.TestCase):

    def test_val_rec_and_ter(self):
        data = rec() + bytes(16)
        self.assertEqual(prs_tbl(SynPe(data), 8192), [{'table_entry_rva': '0x2000', 'selector': '0xf4dae6b', 'target_rva': '0x1000', 'reserved': 0}])

    def test_emp_ter_tab(self):
        self.assertEqual(prs_tbl(SynPe(bytes(16)), 8192), [])

    def test_mis_tab_sec(self):
        with self.assertRaisesRegex(ValueError, 'not inside a PE section'):
            prs_tbl(SynPe(bytes(16), tbl_sec=False), 8192)

    def test_rej_cro_raw_sec(self):
        with self.assertRaisesRegex(ValueError, 'raw section boundary'):
            prs_tbl(SynPe(rec()), 8192)

    def test_rej_tru_rec(self):
        with self.assertRaisesRegex(ValueError, 'Truncated'):
            prs_tbl(SynPe(bytes(7), raw_size=32), 8192)

    def test_rej_non_exe_tar(self):
        with self.assertRaisesRegex(ValueError, 'not executable'):
            prs_tbl(SynPe(rec() + bytes(16), exe2=False), 8192)

    def test_rej_unm_tar(self):
        with self.assertRaisesRegex(ValueError, 'not executable'):
            prs_tbl(SynPe(rec(tgt=36864) + bytes(16)), 8192)

    def test_res_ent_lim(self):
        with self.assertRaisesRegex(ValueError, 'exceeds bound'):
            prs_tbl(SynPe(rec() + bytes(16)), 8192, max_ents=1)

    def test_pre_res_dat_for_aud(self):
        rows = prs_tbl(SynPe(rec(res=7) + bytes(16)), 8192)
        self.assertEqual(rows[0]['reserved'], 7)

class StaArtTes(uni2.TestCase):

    @classmethod
    def setUpClass(cls):
        if not pha.is_dir():
            return
        cls.core = json.loads((pha / 'core-callgraph.json').read_text(encoding='utf-8'))
        cls.vendor = json.loads((pha / 'vendor-dispatch.json').read_text(encoding='utf-8'))
        cls.helpers = json.loads((pha / 'vendor-submit-helpers.json').read_text(encoding='utf-8'))

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_rth_sco_and_sta_mod(self):
        self.assertEqual(len(self.core['functions']), 82)
        self.assertEqual(len(self.core['dynamic_bindings']), 17)
        self.assertFalse(self.core['target_code_executed'])
        self.assertFalse(self.core['hardware_writes'])

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_ven_dis_sco(self):
        self.assertEqual(self.vendor['table_rva'], '0x638000')
        self.assertEqual(self.vendor['table_stride'], 16)
        self.assertEqual(self.vendor['table_entries'], 2184)
        self.assertEqual(len(self.vendor['selected_bindings']), 18)
        self.assertEqual(self.vendor['unresolved_selectors'], [])
        self.assertEqual(len(self.helpers['functions']), 15)

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_all_fun_art_pre_and_anc(self):
        fns2 = self.core['functions'] + self.helpers['functions'] + self.vendor['selected_bindings']
        for item in fns2:
            with self.subTest(function=item['artifact_prefix']):
                stem = pha / item['artifact_prefix']
                raw = json.loads(Path(str(stem) + '.json').read_text(encoding='utf-8'))
                base = 268435456 if stem.name.startswith('RTHAL-') else BASE
                self.assertEqual(raw['addr'], base + int(item['rva'], 16))
                self.assertTrue(raw['ops'])
                self.assertTrue(Path(str(stem) + '.asm').is_file())

    def test_liv_tri_rem_loc(self):
        import ob as bnd_oc_deb
        self.assertFalse(bnd_oc_deb.live)

class ArcRegTes(uni2.TestCase):

    def test_x86_tab_str_and_poi_wid(self):
        data = st2.pack('<II', 268439552, 1878528531) + bytes(8)
        pe = SynPe(data)
        pe.OPTIONAL_HEADER.ImageBase = 268435456
        rows = prs_tbl(pe, 8192, ptr_size=4)
        self.assertEqual(rows[0]['target_rva'], '0x1000')
        self.assertEqual(rows[0]['selector'], '0x6ff81213')

    def test_rej_inv_poi_wid(self):
        with self.assertRaisesRegex(ValueError, 'Pointer size'):
            prs_tbl(SynPe(bytes(16)), 8192, ptr_size=3)

    def test_x86_unt_rec_hit_bou(self):
        pe = SynPe(st2.pack('<II', 268439552, 7))
        pe.OPTIONAL_HEADER.ImageBase = 268435456
        with self.assertRaisesRegex(ValueError, 'raw section boundary'):
            prs_tbl(pe, 8192, ptr_size=4)

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_act_arc_has_dis_bin(self):
        x86 = json.loads((pha / 'vendor32-dispatch.json').read_text(encoding='utf-8'))
        x64 = json.loads((pha / 'vendor-dispatch.json').read_text(encoding='utf-8'))
        self.assertEqual(x86['module']['machine'], '0x14c')
        self.assertEqual(x86['table_stride'], 8)
        self.assertEqual(x86['table_entries'], 2184)
        self.assertEqual(len(x86['selected_bindings']), 18)
        self.assertEqual(x86['unresolved_selectors'], [])
        self.assertEqual(next((b['target_rva'] for b in x86['selected_bindings'] if b['selector'] == '0xf4dae6b')), '0x1f8420')
        self.assertEqual(next((b['target_rva'] for b in x64['selected_bindings'] if b['selector'] == '0xf4dae6b')), '0x22d0f0')

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_x86_art_com(self):
        gro2 = [json.loads((pha / name).read_text(encoding='utf-8')) for name in ['vendor32-dispatch.json', 'vendor32-submit-helpers.json']]
        for item in gro2[0]['selected_bindings'] + gro2[1]['functions']:
            with self.subTest(artifact=item['artifact_prefix']):
                raw = json.loads((pha / (item['artifact_prefix'] + '.json')).read_text(encoding='utf-8'))
                self.assertEqual(raw['addr'], 268435456 + int(item['rva'], 16))
                self.assertTrue(raw['ops'])
                self.assertTrue((pha / (item['artifact_prefix'] + '.asm')).is_file())

    @uni2.skipUnless(pha.is_dir(), 'Local static evidence not present')
    def test_con_evi_is_rep(self):
        from sc import bui
        sav = json.loads((pha / 'overclock-core-findings.json').read_text(encoding='utf-8'))
        self.assertEqual(bui(), sav)
        self.assertEqual(len(sav['claims']), 16)
        self.assertFalse(sav['architecture']['live_branch_traced'])
        self.assertEqual(sav['architecture']['loaded_vendor_module'], 'nvapi32')
if __name__ == '__main__':
    uni2.main()
