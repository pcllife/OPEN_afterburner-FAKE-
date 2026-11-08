# _test_
import copy
import ctypes as C
import unittest as uni2
from unittest.mock import patch as pat2
import ob as oc

def fx():
    return {'editable': True, 'states': [{'id': 0, 'editable': True, 'clocks': [{'domain': 0, 'editable': True, 'delta_khz': 0, 'min_khz': -90000, 'max_khz': 1000000}, {'domain': 4, 'editable': True, 'delta_khz': 0, 'min_khz': -502296, 'max_khz': 3000000}], 'voltages': [{'domain': 0, 'microvolts': 1012500, 'delta_uv': 0}]}]}

class FakeApi:

    def __init__(self, info):
        self.info = copy.deepcopy(info)
        self.writes = []

    def read(self):
        return copy.deepcopy(self.info)

    def set_core(self, val):
        self.writes.append(val)
        self.info['states'][0]['clocks'][0]['delta_khz'] = val

class BndOcTes(uni2.TestCase):

    def test_pin_v1_abi(self):
        self.assertEqual(C.sizeof(oc.Ps), 7316)
        self.assertEqual(oc.Ps.states.offset, 20)
        self.assertEqual(C.sizeof(oc.Pst), 456)
        self.assertEqual(C.sizeof(oc.Clk), 44)
        self.assertEqual(C.sizeof(oc.Vlt), 24)

    def test_tri_req_onl_has_gra_del(self):
        req2 = oc.make_req(13000)
        self.assertEqual(req2.version, 72852)
        self.assertEqual((req2.num_states, req2.num_clocks, req2.num_voltages), (1, 1, 0))
        self.assertEqual(req2.states[0].state_id, 0)
        self.assertEqual(req2.states[0].clocks[0].domain, 0)
        self.assertEqual(req2.states[0].clocks[0].delta.value, 13000)
        mod2 = {ind2 for ind2, val in enumerate(bytes(req2)) if val}
        self.assertLessEqual(mod2, {0, 1, 2, 3, 8, 12, 40, 41, 42, 43})
        self.assertEqual(bytes(req2.states[0].voltages), bytes(C.sizeof(oc.Vlt) * 4))
        self.assertEqual(bytes(req2.states[0].clocks[1:][0]), bytes(44))

    def test_arb_off_are_rej(self):
        for dlt in [-13000, -1, 1, 12000, 14000, 1000000]:
            with self.assertRaises(oc.OcErr):
                oc.make_req(dlt)
        self.assertEqual(oc.make_req(0).states[0].clocks[0].delta.value, 0)

    def test_tem_gat(self):
        oc.chk_pre(fx(), 30)
        for tmp2 in [-1, 55, 80, 100]:
            with self.assertRaises(oc.OcErr):
                oc.chk_pre(fx(), tmp2)

    def test_non_bas_not_ove(self):
        for dom in [0, 4]:
            info = fx()
            next((c for c in info['states'][0]['clocks'] if c['domain'] == dom))['delta_khz'] = 13000
            with self.assertRaises(oc.OcErr):
                oc.chk_pre(info, 30)
        info = fx()
        info['states'][0]['voltages'][0]['delta_uv'] = 1000
        with self.assertRaises(oc.OcErr):
            oc.chk_pre(info, 30)

    def test_not_edi_and_ins_ran_abo(self):
        info = fx()
        info['editable'] = False
        with self.assertRaises(oc.OcErr):
            oc.chk_pre(info, 30)
        info = fx()
        info['states'][0]['clocks'][0]['max_khz'] = 12000
        with self.assertRaises(oc.OcErr):
            oc.chk_pre(info, 30)

    def test_res_ide_bas_doe_not_wri(self):
        info = fx()
        api = FakeApi(info)
        res4 = oc.rst_zero(api, info)
        self.assertTrue(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_tri_del_ret_to_zer(self):
        info = fx()
        api = FakeApi(info)
        api.info['states'][0]['clocks'][0]['delta_khz'] = 13000
        res4 = oc.rst_zero(api, info)
        self.assertTrue(res4['verified'])
        self.assertEqual(api.writes, [0])
        self.assertEqual(oc.ctl_prj(api.read()), oc.ctl_prj(info))

    def test_mem_vol_pro_exc_onl_gra_del(self):
        a = fx()
        b = copy.deepcopy(a)
        b['states'][0]['clocks'][0]['delta_khz'] = 13000
        self.assertEqual(oc.ctl_prj(a, False), oc.ctl_prj(b, False))
        b['states'][0]['clocks'][1]['delta_khz'] = 13000
        self.assertNotEqual(oc.ctl_prj(a, False), oc.ctl_prj(b, False))

class ResRegTes(uni2.TestCase):

    def test_rep_vol_var_doe_not_tri_har_wri(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['voltages'][0]['microvolts'] = 1025000
        self.assertNotEqual(oc.vlt_md(api.read()), oc.vlt_md(base2))
        self.assertEqual(oc.ctl_prj(api.read()), oc.ctl_prj(base2))
        res4 = oc.rst_zero(api, base2)
        self.assertTrue(res4['verified'])
        self.assertEqual(api.writes, [])
        self.assertEqual(res4['writes'], 0)

    def test_vol_del_sti_fai_res_wit_vol_wri(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['voltages'][0]['delta_uv'] = 1000
        with pat2.object(oc.time, 'sleep'):
            res4 = oc.rst_zero(api, base2)
        self.assertFalse(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_onl_p0_cor_is_exc_dur_hol(self):
        base2 = fx()
        ext2 = copy.deepcopy(base2['states'][0])
        ext2['id'] = 5
        base2['states'].append(ext2)
        cur2 = copy.deepcopy(base2)
        cur2['states'][1]['clocks'][0]['delta_khz'] = 13000
        self.assertNotEqual(oc.ctl_prj(cur2, False), oc.ctl_prj(base2, False))

    def test_une_ext_off_not_ove(self):
        base2 = fx()
        api = FakeApi(base2)
        api.info['states'][0]['clocks'][0]['delta_khz'] = 26000
        with pat2.object(oc.time, 'sleep'):
            res4 = oc.rst_zero(api, base2)
        self.assertFalse(res4['verified'])
        self.assertEqual(api.writes, [])

    def test_res_rej_non_cap_bas(self):
        base2 = fx()
        base2['states'][0]['clocks'][0]['delta_khz'] = 13000
        api = FakeApi(base2)
        with self.assertRaises(oc.OcErr):
            oc.rst_zero(api, base2)
        self.assertEqual(api.writes, [])

    def test_rea_set_and_tri_are_loc_bef_har_acc(self):
        self.assertFalse(oc.live)
        with self.assertRaisesRegex(oc.OcErr, 'setter is locked'):
            oc.Nv(ok_set=True)
        with self.assertRaisesRegex(oc.OcErr, 'trials are locked'):
            oc.tri(oc.root2 / 'analysis/phase5/NOT_CREATED', True)
        self.assertFalse((oc.root2 / 'analysis/phase5/NOT_CREATED').exists())
if __name__ == '__main__':
    uni2.main()
