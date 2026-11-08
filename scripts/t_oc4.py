# _test_
import hashlib as has2
import json
from pathlib import Path
import re
import unittest as uni2
import struct as st2
import subprocess as sub2
import tempfile as tem
root2 = Path(__file__).resolve().parents[1]

class OveTes(uni2.TestCase):

    def graph(self):
        path = root2 / 'analysis/phase4/overclock-callgraph.json'
        if not path.is_file():
            self.skipTest('Local static extraction artifacts not present')
        return json.loads(path.read_text(encoding='utf-8'))

    def function(self, rva):
        item = next((item for item in self.graph()['functions'] if item['rva'] == rva))
        return (item, json.loads((root2 / 'analysis/phase4' / (item['artifact_prefix'] + '.json')).read_text()))

    def instructions(self, rva):
        _, f = self.function(rva)
        return {hex(op['offset'] - 268435456): op['disasm'] for op in f['ops']}

    def test_nvi_def_clo_fun_is_not_a_res(self):
        _, f = self.function('0x640a0')
        self.assertEqual([op['disasm'] for op in f['ops']], ['xor eax, eax', 'ret'])

    def test_cor_and_mem_off_hav_dis_dom(self):
        for rva, dom in [('0x86060', 'push 0'), ('0x860d0', 'push 4')]:
            item, f = self.function(rva)
            self.assertIn(dom, [op['disasm'] for op in f['ops']])
            self.assertTrue(any(('PS20_SetClockBoost@' in e['target'] for e in item['calls_and_tail_jumps'])))

    def test_pst_set_con_req_wit_loc_ran_rea(self):
        item, f = self.function('0x85fa0')
        self.assertIn('mov dword [ebp - 0x1c98], 0x11c94', [op['disasm'] for op in f['ops']])
        tar = [e['target'] for e in item['calls_and_tail_jumps'] if 'call' in e['kind']]
        self.assertTrue(any(('GpuSetPstates20@' in t for t in tar)))
        self.assertFalse(any(('GetClockBoost' in t or 'GpuGetPstates20' in t for t in tar)))
        text = list(self.instructions('0x85fa0').values())
        self.assertIn('neg eax', text)
        self.assertIn('sbb eax, eax', text)
        self.assertIn('inc eax', text)

    def test_upp_fre_off_pat_doe_not_bra_on_cor_res(self):
        ins = self.instructions('0x63f30')
        self.assertIn('PS20_SetCoreClockBoost', ins['0x64002'])
        self.assertEqual(ins['0x64007'], 'push dword [ebp + 0xc]')
        self.assertIn('PS20_SetMemoryClockBoost', ins['0x64010'])
        self.assertEqual(ins['0x64015'], 'mov ecx, dword [esi + 0xdb4]')

    def test_pow_uni_con_and_fin_sta_not_che(self):
        ins = self.instructions('0x86f40')
        self.assertEqual(ins['0x86fe5'], 'imul eax, dword [ebp + 8], 0x3e8')
        self.assertEqual(ins['0x87017'], 'cmovae esi, eax')
        self.assertEqual(ins['0x87030'], 'cmovbe edx, esi')
        self.assertIn('GpuClientPowerPoliciesSetStatus', ins['0x87036'])
        self.assertEqual(ins['0x8703b'], 'pop esi')

    def test_leg_sub_fai_ret_fal(self):
        ins = self.instructions('0x86c70')
        self.assertIn('GpuSetPerfClocks', ins['0x86ea5'])
        self.assertEqual(ins['0x86eac'], 'jne 0x10086f16')
        self.assertIn('GpuSetPerfClocks', ins['0x86ed2'])
        self.assertEqual(ins['0x86ed9'], 'jne 0x10086f16')
        self.assertEqual(ins['0x86f19'], 'xor eax, eax')

    def test_rea_onl_map_and_cli_no_con_dis(self):
        src2 = (root2 / 'src/shm.rs').read_text()
        self.assertIn('OpenFileMappingW(FILE_MAP_READ', src2)
        self.assertIn('MapViewOfFile(self.0, FILE_MAP_READ', src2)
        for pro in ['FILE_MAP_WRITE', 'FILE_MAP_ALL_ACCESS', 'PostMessage', 'SendMessage', 'CreateProcess', 'write_volatile', 'copy_nonoverlapping']:
            self.assertNotIn(pro, src2)
        ap = (root2 / 'src/cm.rs').read_text(encoding='utf-8-sig')
        self.assertNotIn('unsafe', ap)
        self.assertNotIn('DeviceIoControl', ap)
        ids = (root2 / 'src/ni.rs').read_text()
        self.assertNotRegex(ids, 'pub const (?:[A-Z0-9]+_)*SET_[A-Z0-9_]+:')

    def test_sca_lay_is_gro_in_bun_sdk(self):
        sdk_p = root2 / 'afterb/MSI Afterburner/SDK/Include/MACMSharedMemory.h'
        if not sdk_p.is_file():
            self.skipTest('Local SDK fixture not present')
        sdk = sdk_p.read_text(errors='replace')
        fie2 = re.findall('^\\s*(DWORD|LONG)\\s+(dw\\w+);', sdk.split('typedef struct MACM_SHARED_MEMORY_GPU_ENTRY', 1)[1], re.M)
        offs2 = {name: (ind2 * 4, kind) for ind2, (kind, name) in enumerate(fie2)}
        self.assertEqual(offs2['dwCoreClockBoostCur'], (188, 'LONG'))
        self.assertEqual(offs2['dwMemoryClockBoostCur'], (204, 'LONG'))
        self.assertEqual(offs2['dwFanSpeedMin'], (60, 'DWORD'))
        self.assertEqual(len(fie2) * 4, 276)
        self.assertIn('#define MACM_SHARED_MEMORY_VF_CURVE_POINTS_MAX', sdk)

    def test_off_cli_use_dec_sig_uni_and_nev_dis_pen_com(self):
        exe = root2 / 'target/debug/abx.exe'
        if not exe.is_file():
            self.skipTest('Build Rust binary before CLI integration test')
        blob = bytearray(36 + 3760)
        st2.pack_into('<9I', blob, 0, 1296122701, 131075, 36, 1, 3760, 0, 0, 12345, 11206657)
        st2.pack_into('<I', blob, 36, 2048)
        st2.pack_into('<4i', blob, 36 + 188, -12500, -90000, 135000, 0)
        blob[36 + 3500:36 + 3500 + 12] = b'TEST_ONLY_OC'
        blob[36 + 3500 + 12] = 0
        with tem.TemporaryDirectory() as dir2:
            file = Path(dir2) / 'SYNTHETIC_NOT_HARDWARE.bin'
            file.write_bytes(blob)
            bef = file.read_bytes()
            res4 = sub2.run([str(exe), 'oc-info', '--from', str(file)], capture_output=True, check=True)
            text = res4.stdout.decode('utf-8')
            self.assertIn('pending_command=0xab0001', text)
            self.assertIn('core_clock_offset\t-12500\t-90000\t135000\t0\tkHz', text)
            self.assertIn('NOT stability or safety guarantees', text)
            self.assertEqual(file.read_bytes(), bef)

    def test_off_cli_rej_tru_sna(self):
        exe = root2 / 'target/debug/abx.exe'
        if not exe.is_file():
            self.skipTest('Build Rust binary before CLI integration test')
        with tem.TemporaryDirectory() as dir2:
            file = Path(dir2) / 'TRUNCATED.bin'
            file.write_bytes(b'MCAM')
            res4 = sub2.run([str(exe), 'oc-info', '--from', str(file)], capture_output=True)
            self.assertNotEqual(res4.returncode, 0)
            self.assertIn('truncated MACM header', res4.stderr.decode('utf-8'))

    def test_cli_has_no_set_com(self):
        exe = root2 / 'target/debug/abx.exe'
        if not exe.is_file():
            self.skipTest('Build Rust binary before CLI integration test')
        res4 = sub2.run([str(exe), 'oc-info', '--set', '100'], capture_output=True)
        self.assertNotEqual(res4.returncode, 0)
        self.assertIn('invalid arguments', res4.stderr.decode('utf-8'))

    def test_sdk_cur_lay_mat_par_off(self):
        from so import Cur, Ent
        import ctypes as cty
        self.assertEqual(cty.sizeof(Ent), 3760)
        self.assertEqual(cty.sizeof(Cur), 3224)
        self.assertEqual(Ent.curve.offset, 276)
        self.assertEqual(Ent.gpu_id.offset, 3500)
        self.assertEqual(Cur.lock_plus_one.offset, 3084)
        self.assertEqual(Cur.power_count.offset, 3088)
        self.assertEqual(Cur.thermal_count.offset, 3156)

    def test_vf_err_is_deb_mod_not_an_ign_suc(self):
        ins = self.instructions('0x882b0')
        self.assertEqual(ins['0x883b9'], 'cmp edx, 0xffffff27')
        self.assertEqual(ins['0x883cd'], 'sete al')
        hea = (root2 / 'tools/nvapi-headers/nvapi_lite_common.h').read_text()
        self.assertRegex(hea, 'NVAPI_GPU_IN_DEBUG_MODE\\s*= -217')

    def test_art_ret_ori_sam_ide(self):
        gra = self.graph()
        self.assertFalse(gra['hardware_calls_executed'])
        self.assertEqual(len(gra['functions']), 54)
        for mod3 in gra['modules']:
            act = has2.sha256((root2 / 'afterb/MSI Afterburner' / mod3['path']).read_bytes()).hexdigest()
            self.assertEqual(act, mod3['sha256'])
        for item in gra['functions']:
            self.assertGreater(item['ops'], 0)
            for ext in ['.asm', '.json']:
                self.assertTrue((root2 / 'analysis/phase4' / (item['artifact_prefix'] + ext)).is_file())
if __name__ == '__main__':
    uni2.main()
