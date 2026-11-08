# _test_
import hashlib as has2, json, re, unittest as uni2
from pathlib import Path
root2 = Path(__file__).resolve().parents[1]

class PhaThrTes(uni2.TestCase):

    def test_nva_ids_are_rea_or_lif(self):
        text = (root2 / 'src/ni.rs').read_text()
        ents2 = re.findall(r'pub const (\w+): u32 = (0x[0-9a-f]+);', text)
        self.assertEqual(len(ents2), 10)
        nam3 = {const: int(val, 16) for const, val in ents2}
        self.assertEqual(nam3['GET_DYN'], 1625215725)
        self.assertEqual(nam3['GET_CLK'], 3702920899)
        exp = {'INIT': 22079528, 'UNLD': 3526090110, 'ENUM_GPU': 3853292063, 'GET_NM': 3471740575, 'GET_DYN': 1625215725, 'GET_CLK': 3702920899, 'GET_THM': 3814984278, 'GET_TACH': 1600160533, 'GET_MEM': 133804904, 'GET_DRV': 690399917}
        self.assertEqual(nam3, exp)
        from gi import fns
        self.assertEqual(set(nam3), set(fns))
        for const, val in ents2:
            name = fns[const]
            self.assertNotIn('_Set', name)
            self.assertTrue(name.startswith(('NvAPI_GPU_Get', 'NvAPI_SYS_Get')) or name in ['NvAPI_Initialize', 'NvAPI_Unload', 'NvAPI_EnumPhysicalGPUs'])

    def test_cac_off_hea_has(self):
        dir2 = root2 / 'tools/nvapi-headers'
        if not (dir2 / 'sources.json').is_file():
            self.skipTest('Official header cache not present')
        rpt = json.loads((dir2 / 'sources.json').read_text())
        self.assertRegex(rpt['commit'], '^[0-9a-f]{40}$')
        for item in rpt['files']:
            self.assertIn('/NVIDIA/nvapi/' + rpt['commit'] + '/', item['source'])
            self.assertEqual(has2.sha256((dir2 / item['file']).read_bytes()).hexdigest(), item['sha256'])

    def test_run_mod_exp_no_har_set(self):
        src2 = (root2 / 'src/nv.rs').read_text(encoding='utf-8-sig')
        self.assertIn('LOAD_LIBRARY_SEARCH_SYSTEM32', src2)
        self.assertNotIn('DeviceIoControl', src2)
        self.assertNotIn('OpenFileMapping', src2)
        self.assertNotIn('MACMSharedMemory', src2)
        self.assertNotIn('GPU_SET_', src2)
        self.assertIn('ERR_VER', src2)

    def trace(self):
        path = root2 / 'analysis/phase3/macm-callgraph.json'
        if not path.is_file():
            self.skipTest('Local trace not present')
        return {f['rva']: f for f in json.loads(path.read_text())['functions']}

    def assembly(self, rva):
        f = self.trace()[rva]
        return (root2 / 'analysis/phase3' / (f['artifact_prefix'] + '.asm')).read_text()

    def test_dis_dis_app_fro_sta_onl(self):
        src2 = self.assembly('0x601b9')
        self.assertIn('sub eax, 0xab0000', src2)
        self.assertRegex(src2, '004601f1 .*push 0')
        self.assertRegex(src2, '004601fc .*push 1')
        self.assertIn('0x450755', src2)

    def test_com_res_is_not_tru_sha_tai(self):
        src2 = self.assembly('0x60403')
        self.assertIn('mov dword [eax + 0x20], 0', src2)
        self.assertIn('ReleaseMutex', src2)
        self.assertIn('CloseHandle', src2)
        self.assertGreater(self.trace()['0x60403']['ops'], 20)

    def test_pro_loa_app_onl_whe_fla_is_set(self):
        src2 = self.assembly('0x5553c')
        self.assertRegex(src2, '0045773e .*cmp dword \\[ebp \\+ 0x10\\], 0')
        self.assertRegex(src2, '00457748 .*je 0x45775c')
        self.assertRegex(src2, '00457755 .*call 0x459022')

    def test_act_app_rea_hal_set(self):
        fn = self.trace()['0x59022']
        tar = [edge['target'] for edge in fn['calls_and_tail_jumps']]
        for name in ['SetMultiGpuClocks', 'SetMultiGpuClockBoost', 'SetMultiGpuPowerLimit', 'SetVoltageFrequencyCurve']:
            self.assertTrue(any((name in val and 'RTHAL.dll!' in val for val in tar)))

    def test_mul_hal_bri_rea_sin_gpu_set(self):
        path = root2 / 'analysis/phase3/rthal-submit-bridge.json'
        if not path.is_file():
            self.skipTest('HAL bridge artifacts not present')
        rpt = json.loads(path.read_text())
        met3 = {item['name']: item for item in rpt['functions']}
        for mul, sin in [('SetMultiGpuClocks', 'SetClocks'), ('SetMultiGpuClockBoost', 'SetClockBoost'), ('SetMultiGpuPowerLimit', 'SetPowerLimit')]:
            tar = [edge['target'] for edge in met3['CHAL.' + mul]['calls_and_tail_jumps']]
            self.assertTrue(any((val.startswith('?' + sin + '@CHAL@@') for val in tar)))

    def test_sou_ada_rea_mac_not_onl_pro_fil(self):
        src2 = self.assembly('0x11c29')
        self.assertIn('MACMSharedMemory', src2)
        self.assertIn('cmp dword [esi], 0x4d41434d', src2)
        self.assertIn('GetSelectedGpu', src2)
        self.assertIn('0xeb0', src2)
if __name__ == '__main__':
    uni2.main()
