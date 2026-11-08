# _test_
import copy
import ctypes as C
import json
import tempfile as tem
import unittest as uni2
from pathlib import Path
from unittest.mock import Mock, patch as pat2
import oc as oc
import ob as old
from t_ob import fx as v_1_fx, FakeApi

def fx():
    data = v_1_fx()
    data['relative_voltages'] = [{'domain': 0, 'delta_uv': 0, 'microvolts': 0}]
    return data

def ctl():
    return {'gpu_id': 'VEN_10DE&DEV_1402&SUBSYS_238819DA&REV_A1&BUS_1&DEV_0&FN_0', 'pending_command': 0, 'core_offset_khz': 0, 'memory_offset_khz': 0, 'power_limit_percent': 100, 'thermal_limit_c': 80, 'fan_mode': 1, 'voltage_control_supported': False, 'voltage_offset_supported': True, 'voltage_offsets_mv': {'core': 0, 'memory': None, 'aux': None, 'aux2': None}, 'capabilities': 2176}

class AuthTes(uni2.TestCase):

    def test_def_loc_and_old_ent_unc(self):
        self.assertFalse(oc.live)
        self.assertIsNone(oc.run_dir)
        self.assertFalse(old.live)
        self.assertEqual(oc.hold_sec, 3.0)
        with self.assertRaises(oc.OcErr):
            oc.Nv(ok_set=True)
        with self.assertRaises(old.OcErr):
            old.Nv(ok_set=True)

    def test_ack_req_bef_any_acc(self):
        with pat2.object(oc, '_orig_tri') as inv3:
            with self.assertRaises(oc.OcErr):
                oc.tri(Path('NOT_CREATED'), False)
            inv3.assert_not_called()

    def test_fai_clo_aut_win(self):
        with tem.TemporaryDirectory() as temp:
            root = Path(temp)

            def fail(dir2, ack):
                self.assertTrue(oc.live)
                self.assertEqual(oc.run_dir, dir2)
                raise oc.OcErr('simulated failure before hardware access')
            with pat2.object(oc, 'root2', root), pat2.object(oc, '_orig_tri', side_effect=fail):
                with self.assertRaisesRegex(oc.OcErr, 'simulated'):
                    oc.tri(root / 'analysis/phase9/one', True)
            self.assertFalse(oc.live)
            self.assertIsNone(oc.run_dir)

    def test_exi_dir_ref_bef_wri(self):
        with tem.TemporaryDirectory() as temp:
            root = Path(temp)
            d = root / 'analysis/phase9/one'
            d.mkdir(parents=True)
            with pat2.object(oc, 'root2', root), pat2.object(oc, '_orig_tri') as inv3:
                with self.assertRaises(oc.OcErr):
                    oc.tri(d, True)
                inv3.assert_not_called()

    def test_inv_rec_pla_nev_con_api(self):
        with tem.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / 'analysis/phase9/one/plan.json'
            p.parent.mkdir(parents=True)
            p.write_text('{}', encoding='utf-8')
            with pat2.object(oc, 'root2', root), pat2.object(oc, '_orig_wd') as inv3:
                with self.assertRaises(oc.OcErr):
                    oc.wd(p)
                inv3.assert_not_called()
            self.assertFalse(oc.live)

class PktAndSetTes(uni2.TestCase):

    def test_v2_lay_inc_ov_tai(self):
        self.assertEqual(C.sizeof(oc.Ps2), 7416)
        self.assertEqual(oc.Ps2.num_ov_voltages.offset, 7316)
        self.assertEqual(oc.Ps2.ov_voltages.offset, 7320)

    def test_onl_zer_and_130_req(self):
        for val in (0, 13000):
            data = bytes(oc.make_req(val))
            desc = oc.insp_clk_req(data)
            self.assertEqual(desc['delta_khz'], val)
            self.assertEqual(desc['domain'], 0)
            self.assertEqual(desc['num_base_voltages'], 0)
        for val in (-1, 1, 12000, 14000, 26000):
            with self.assertRaises(oc.OcErr):
                oc.make_req(val)

    def test_v2_rea_use_v2_and_dec_ov(self):
        api = object.__new__(oc.Nv)
        api.gpu = None

        def fake_get(gpu, ptr):
            p = C.cast(ptr, C.POINTER(oc.Ps2)).contents
            self.assertEqual(p.version, 138488)
            p.num_ov_voltages = 1
            p.ov_voltages[0].domain = 0
            p.ov_voltages[0].delta.value = 12500
            return 0
        api.get = fake_get
        self.assertEqual(api.read()['relative_voltages'][0]['delta_uv'], 12500)

    def test_v2_bad_cou_ref(self):
        api = object.__new__(oc.Nv)
        api.gpu = None

        def fake_get(gpu, ptr):
            C.cast(ptr, C.POINTER(oc.Ps2)).contents.num_ov_voltages = 5
            return 0
        api.get = fake_get
        with self.assertRaises(oc.OcErr):
            api.read()

    def test_set_loc_bef_pac_or_cal(self):
        api = object.__new__(oc.Nv)
        api.setter = Mock()
        with self.assertRaises(oc.OcErr):
            api.set_core(13000)
        api.setter.assert_not_called()

    def test_raw_sta_zer_and_exa_req_log(self):
        api = object.__new__(oc.Nv)
        api.gpu = None
        api.write_audit = []
        cap2 = []

        def fake_set(gpu, ptr):
            cap2.append(bytes(C.cast(ptr, C.POINTER(oc.Ps)).contents))
            return 0
        api.setter = fake_set
        with tem.TemporaryDirectory() as temp:
            with pat2.object(oc, 'live', True), pat2.object(oc, 'run_dir', Path(temp)):
                api.set_core(13000)
                api.set_core(0)
            log = json.loads(next(Path(temp).glob('api-writes-*.json')).read_text())
            self.assertEqual([x['raw_status'] for x in log['writes']], [0, 0])
        self.assertEqual([oc.insp_clk_req(p)['delta_khz'] for p in cap2], [13000, 0])

    def test_non_raw_sta_rai_and_is_log(self):
        api = object.__new__(oc.Nv)
        api.gpu = None
        api.write_audit = []
        api.setter = Mock(return_value=-1)
        with tem.TemporaryDirectory() as temp:
            with pat2.object(oc, 'live', True), pat2.object(oc, 'run_dir', Path(temp)):
                with self.assertRaisesRegex(oc.OcErr, 'status -1'):
                    api.set_core(13000)
            self.assertEqual(api.write_audit[0]['raw_status'], -1)
        api.setter.assert_called_once()

class GateTes(uni2.TestCase):

    def test_unl_off_cap_wit_zer_off_all(self):
        with pat2.object(oc, 'chk_pro'):
            oc.chk_ctl(ctl())

    def test_uns_mac_con_rej(self):
        for key, val in [('pending_command', 1), ('core_offset_khz', 13000), ('memory_offset_khz', 13000), ('power_limit_percent', 110), ('thermal_limit_c', 90), ('fan_mode', 0), ('voltage_control_supported', True)]:
            data = ctl()
            data[key] = val
            with self.subTest(key=key), pat2.object(oc, 'chk_pro'):
                with self.assertRaises(oc.OcErr):
                    oc.chk_ctl(data)

    def test_man_vol_off_rej(self):
        for key in ('core', 'memory', 'aux', 'aux2'):
            data = ctl()
            data['voltage_offsets_mv'][key] = 1
            with pat2.object(oc, 'chk_pro'):
                with self.assertRaises(oc.OcErr):
                    oc.chk_ctl(data)

    def test_con_vol_pro_gua(self):
        with tem.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / 'afterb/MSI Afterburner/Profiles/MSIAfterburner.cfg'
            p.parent.mkdir(parents=True)
            with pat2.object(oc, 'root2', root):
                for val in ('0', ' 0  '):
                    p.write_text('[Settings]\nForceConstantVoltage=' + val + '\n', encoding='utf-8')
                    oc.chk_pro()
                for text in ('ForceConstantVoltage=1\n', 'ForceConstantVoltage=0\nForceConstantVoltage=1\n', ''):
                    p.write_text(text, encoding='utf-8')
                    with self.assertRaises(oc.OcErr):
                        oc.chk_pro()

    def test_tem_and_rel_vol_gat(self):
        oc.chk_pre(fx(), 24)
        for tmp2 in (-1, 55, 90):
            with self.assertRaises(oc.OcErr):
                oc.chk_pre(fx(), tmp2)
        info = fx()
        info['relative_voltages'][0]['delta_uv'] = 1000
        with self.assertRaises(oc.OcErr):
            oc.chk_pre(info, 24)
        info = fx()
        info['states'][0]['editable'] = False
        with self.assertRaises(oc.OcErr):
            oc.chk_pre(info, 24)

    def test_non_con_com(self):
        base2 = ctl()
        now = copy.deepcopy(base2)
        now['core_offset_khz'] = 13000
        with pat2.object(oc, 'chk_pro'):
            oc.chk_non_tgt_ctl(now, base2)
        for key, val in [('memory_offset_khz', 13), ('power_limit_percent', 110), ('fan_mode', 0), ('pending_command', 1)]:
            now = copy.deepcopy(base2)
            now[key] = val
            with pat2.object(oc, 'chk_pro'):
                with self.assertRaises(oc.OcErr):
                    oc.chk_non_tgt_ctl(now, base2)

class RecTes(uni2.TestCase):

    def test_bas_vol_met_doe_not_tri_wri(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['voltages'][0]['microvolts'] += 12500
        api.info['relative_voltages'][0]['microvolts'] += 12500
        self.assertNotEqual(oc.vlt_md(api.read()), oc.vlt_md(base2))
        res4 = oc.rst_zero(api, base2)
        self.assertTrue(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_obs_tri_off_is_res_onl_to_zer(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['clocks'][0]['delta_khz'] = 13000
        with pat2.object(oc.time, 'sleep'):
            res4 = oc.rst_zero(api, base2)
        self.assertTrue(res4['verified'])
        self.assertEqual(api.writes, [0])

    def test_rel_vol_del_fai_wit_vol_wri(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['relative_voltages'][0]['delta_uv'] = 1000
        with pat2.object(oc.time, 'sleep'):
            res4 = oc.rst_zero(api, base2)
        self.assertFalse(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_ext_off_not_ove(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['clocks'][0]['delta_khz'] = 26000
        with pat2.object(oc.time, 'sleep'):
            res4 = oc.rst_zero(api, base2)
        self.assertFalse(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_non_ori_ref(self):
        base2 = fx()
        base2['states'][0]['clocks'][0]['delta_khz'] = 13000
        with self.assertRaises(oc.OcErr):
            oc.rst_zero(FakeApi(base2), base2)
if __name__ == '__main__':
    uni2.main()
