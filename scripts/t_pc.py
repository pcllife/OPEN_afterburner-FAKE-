# _test_
import ast
from pathlib import Path
import struct as st2
import subprocess as sub2
import sys
import tempfile as tem
import unittest as uni2
from pc import PcErr, make_clk_req, insp_clk_req, plan_clk_cha, cmp_clk_rea, rth_boo_from_sts
from pp import v_1_byt, v_2_byt, prs
root2 = Path(__file__).resolve().parents[1]

def syn_sna(gfx=-5000, mem2=0, vlt_dlt=0, rep_vlt=1000000, ov_dlt=0):
    data = bytearray(v_2_byt)
    st2.pack_into('<5I', data, 0, 138488, 1, 1, 2, 1)
    st2.pack_into('<2I', data, 20, 0, 1)
    for off2, dom, dlt in [(28, 0, gfx), (72, 4, mem2)]:
        st2.pack_into('<3I3i', data, off2, dom, 0, 1, dlt, -100000, 100000)
        st2.pack_into('<I', data, off2 + 24, 1000000)
    st2.pack_into('<3I3i', data, 380, 0, 1, rep_vlt, vlt_dlt, -50000, 50000)
    st2.pack_into('<I', data, v_1_byt, 1)
    st2.pack_into('<3I3i', data, v_1_byt + 4, 0, 1, rep_vlt, ov_dlt, -50000, 50000)
    return bytes(data)

def rep(data, off2, val, fmt='<I'):
    out = bytearray(data)
    st2.pack_into(fmt, out, off2, val)
    return bytes(out)

class ClkReqTes(uni2.TestCase):

    def test_gra_req_mat_ind_fie_ora(self):
        act = make_clk_req(0, 13000)
        exp2 = bytearray(7316)
        for off2, val in [(0, 72852), (8, 1), (12, 1), (40, 13000)]:
            st2.pack_into('<I', exp2, off2, val)
        self.assertEqual(act, bytes(exp2))
        dec = prs(act, 'request')
        self.assertEqual(dec['states'][0]['clocks'][0]['frequency_delta']['value'], 13000)
        self.assertEqual(dec['num_base_voltages_per_state'], 0)

    def test_mem_neg_del_is_not_res(self):
        raw = make_clk_req(4, -25000)
        self.assertEqual(st2.unpack_from('<I', raw, 28)[0], 4)
        self.assertEqual(st2.unpack_from('<i', raw, 40)[0], -25000)
        self.assertEqual(insp_clk_req(raw)['domain_name'], 'memory')

    def test_sig_int_bou_enc_wit_app(self):
        for val in [-(1 << 31), (1 << 31) - 1, 0]:
            self.assertEqual(insp_clk_req(make_clk_req(0, val))['delta_khz'], val)

    def test_inv_del_typ_and_ove_rej(self):
        for val in [True, 1.0, '13000', 1 << 31, -(1 << 31) - 1]:
            with self.subTest(value=val), self.assertRaises(PcErr):
                make_clk_req(0, val)

    def test_uns_dom_rej(self):
        for dom in [True, 7, 8, 32, -1]:
            with self.subTest(domain=dom), self.assertRaises(PcErr):
                make_clk_req(dom, 0)

    def test_req_len_is_exa(self):
        raw = make_clk_req(0, 0)
        for data in [raw[:-1], raw + b'\x00']:
            with self.assertRaises(PcErr):
                insp_clk_req(data)

    def test_wro_ver_rej(self):
        with self.assertRaises(PcErr):
            insp_clk_req(rep(make_clk_req(0, 0), 0, 138488))

    def test_vol_fla_and_unu_byt_rej(self):
        for off2 in [4, 16, 24, 32, 36, 44, 48, 380, 7312]:
            with self.subTest(offset=off2), self.assertRaises(PcErr):
                insp_clk_req(rep(make_clk_req(0, 0), off2, 1))

    def test_get_sna_can_be_rep_as_req(self):
        with self.assertRaises(PcErr):
            insp_clk_req(syn_sna())

    def test_leg_loc_bui_agr_for_its_two_val(self):
        from ob import make_req
        for dlt in [0, 13000]:
            self.assertEqual(make_clk_req(0, dlt), bytes(make_req(dlt)))

    def test_rth_boo_dis_raw_err_sta(self):
        self.assertEqual(rth_boo_from_sts(0), 1)
        for sts2 in [-104, -217, -9, 1, -(1 << 31)]:
            self.assertEqual(rth_boo_from_sts(sts2), 0)

class PlanTes(uni2.TestCase):

    def test_non_ori_off_is_pre_for_res(self):
        res4 = plan_clk_cha(syn_sna(gfx=-5000), 0, 13000)
        self.assertEqual(res4['request']['delta_khz'], 13000)
        self.assertEqual(res4['restore_original']['delta_khz'], -5000)
        self.assertFalse(res4['hardware_writes'])
        self.assertFalse(res4['invocation_available'])
        self.assertFalse(res4['gpu_identity_verified'])

    def test_mem_pla_is_ind(self):
        res4 = plan_clk_cha(syn_sna(mem2=7000), 4, -9000)
        self.assertEqual(res4['previous_delta_khz'], 7000)
        self.assertEqual(res4['request']['domain'], 4)

    def test_rep_bou_are_inc(self):
        for val in [-100000, 100000]:
            self.assertTrue(plan_clk_cha(syn_sna(), 0, val)['offline_contract_checks_passed'])

    def test_out_of_ran_or_inv_ran_rej(self):
        for val in [-100001, 100001]:
            with self.assertRaises(PcErr):
                plan_clk_cha(syn_sna(), 0, val)
        with self.assertRaises(PcErr):
            plan_clk_cha(rep(syn_sna(), 44, 200000, '<i'), 0, 13000)

    def test_edi_req_at_all_thr_lev(self):
        for off2 in [4, 24, 36]:
            with self.subTest(offset=off2), self.assertRaises(PcErr):
                plan_clk_cha(rep(syn_sna(), off2, 0), 0, 13000)

    def test_res_fla_and_unk_uni_rej(self):
        for off2, val in [(4, 3), (24, 3), (36, 3), (32, 99)]:
            with self.subTest(offset=off2), self.assertRaises(PcErr):
                plan_clk_cha(rep(syn_sna(), off2, val), 0, 13000)

    def test_mis_p0_or_dom_rej(self):
        for data in [rep(syn_sna(), 20, 8), rep(syn_sna(), 28, 7)]:
            with self.assertRaises(PcErr):
                plan_clk_cha(data, 0, 13000)

    def test_dup_dom_rej(self):
        with self.assertRaisesRegex(PcErr, 'Duplicate'):
            plan_clk_cha(rep(syn_sna(), 72, 0), 0, 13000)

    def test_tra_sna_byt_rej(self):
        with self.assertRaises(PcErr):
            plan_clk_cha(syn_sna() + b'\x00', 0, 13000)

class ReaTes(uni2.TestCase):

    def test_tar_mat_pas_fie_com_onl(self):
        res4 = cmp_clk_rea(syn_sna(), syn_sna(gfx=13000), 0, 13000)
        self.assertTrue(res4['control_fields_match'])
        self.assertFalse(res4['gpu_identity_verified'])
        self.assertFalse(res4['transport_status_verified'])

    def test_bas_vol_met_cha_is_not_a_con_cha(self):
        res4 = cmp_clk_rea(syn_sna(), syn_sna(gfx=13000, rep_vlt=1012500), 0, 13000)
        self.assertTrue(res4['control_fields_match'])
        self.assertEqual(len(res4['reported_voltage_metadata_changes']), 2)

    def test_vol_off_cha_fai(self):
        for kwa in [{'vlt_dlt': 1000}, {'ov_dlt': 1000}]:
            res4 = cmp_clk_rea(syn_sna(), syn_sna(gfx=13000, **kwa), 0, 13000)
            self.assertFalse(res4['control_fields_match'])
            self.assertTrue(res4['unexpected_control_changes'])

    def test_unr_mem_del_cha_fai(self):
        res4 = cmp_clk_rea(syn_sna(), syn_sna(gfx=13000, mem2=1000), 0, 13000)
        self.assertFalse(res4['control_fields_match'])
        self.assertEqual(res4['unexpected_control_changes'][0]['key'], 'clock:P0:D4')

    def test_tar_mis_or_mis_fai(self):
        for data in [syn_sna(gfx=12000), rep(syn_sna(gfx=13000), 28, 7)]:
            self.assertFalse(cmp_clk_rea(syn_sna(), data, 0, 13000)['control_fields_match'])

    def test_mis_unr_con_fai(self):
        data = rep(syn_sna(gfx=13000), 12, 1)
        self.assertFalse(cmp_clk_rea(syn_sna(), data, 0, 13000)['control_fields_match'])

    def test_res_is_to_ori_non_del(self):
        res4 = cmp_clk_rea(syn_sna(gfx=13000), syn_sna(gfx=-5000), 0, -5000)
        self.assertTrue(res4['control_fields_match'])

class IsoTes(uni2.TestCase):

    def test_mod_imp_onl_off_dep(self):
        tree = ast.parse((root2 / 'scripts/pc.py').read_text(encoding='utf-8'))
        all2 = {'__future__', 'argparse', 'hashlib', 'json', 'pathlib', 'struct', 'pp'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all((x.name in all2 for x in node.names)))
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, all2)

    def test_exi_liv_tri_rem_loc(self):
        import ob as bnd_oc_deb
        self.assertFalse(bnd_oc_deb.live)
        with self.assertRaises(bnd_oc_deb.OcErr):
            bnd_oc_deb.Nv(ok_set=True)

    def test_cli_wri_onl_new_off_fil(self):
        with tem.TemporaryDirectory() as fol:
            path = Path(fol) / 'synthetic.bin'
            cmd = [sys.executable, str(root2 / 'scripts/pc.py'), 'request', '--domain', 'graphics', '--delta-khz', '13000', '--out', str(path)]
            fir = sub2.run(cmd, capture_output=True)
            self.assertEqual(fir.returncode, 0, fir.stderr)
            exp2 = path.read_bytes()
            self.assertEqual(exp2, make_clk_req(0, 13000))
            sec2 = sub2.run(cmd, capture_output=True)
            self.assertEqual(sec2.returncode, 2)
            self.assertEqual(path.read_bytes(), exp2)

class EviTes(uni2.TestCase):

    @uni2.skipUnless((root2 / 'analysis/phase7').is_dir(), 'Local static evidence not present')
    def test_con_is_rep(self):
        import json
        from ct import bui_con
        sav = json.loads((root2 / 'analysis/phase8/clock-call-contract.json').read_text(encoding='utf-8'))
        self.assertEqual(bui_con(), sav)

    @uni2.skipUnless((root2 / 'analysis/phase7').is_dir(), 'Local static evidence not present')
    def test_fie_off_mat_ind_dec_lay(self):
        from ct import bui_con
        fie2 = {f['name']: f['offset'] for f in bui_con()['request']['fields']}
        self.assertEqual(fie2, {'version': 0, 'numPstates': 8, 'numClocks': 12, 'numBaseVoltages': 16, 'pstates[0].pstateId': 20, 'pstates[0].clocks[0].domainId': 28, 'pstates[0].clocks[0].freqDelta_kHz.value': 40})

    @uni2.skipUnless((root2 / 'analysis/phase7').is_dir(), 'Local static evidence not present')
    def test_wra_and_ven_suc_con_are_dis(self):
        from ct import bui_con
        val = bui_con()
        self.assertEqual(val['vendor']['success_status'], 0)
        self.assertIn('status 0 becomes 1', val['wrapper']['return'])
        self.assertEqual(val['vendor']['bindings']['x86']['target_rva'], '0x1f8420')

    def test_det_sig_rou(self):
        import random as ran
        rng = ran.Random(7316)
        for _ in range(128):
            dlt = rng.randint(-(1 << 31), (1 << 31) - 1)
            dom = rng.choice([0, 4])
            raw = make_clk_req(dom, dlt)
            par3 = prs(raw, 'request')
            clk = par3['states'][0]['clocks'][0]
            self.assertEqual(clk['domain'], dom)
            self.assertEqual(clk['frequency_delta']['value'], dlt)

class RdOnlyCapIsoTes(uni2.TestCase):

    def test_cap_all_exc_set(self):
        from cap import rd_only_ids
        self.assertEqual(len(rd_only_ids), 8)
        self.assertNotIn(256749163, rd_only_ids)

    def test_cap_rej_set_bef_any_lib_acc(self):
        from cap import Cap, OcErr
        api = Cap.__new__(Cap)
        for sel2 in [256749163, 3735928559]:
            with self.assertRaisesRegex(OcErr, 'getter-only'):
                api.resolve(sel2, None, [])

    def test_exi_cap_dir_rej_bef_liv_acc(self):
        with tem.TemporaryDirectory() as fol:
            cmd = [sys.executable, str(root2 / 'scripts/cap.py'), '--out-dir', fol]
            res4 = sub2.run(cmd, capture_output=True)
            self.assertEqual(res4.returncode, 2)
            self.assertIn(b'already exists', res4.stderr)
            self.assertEqual(list(Path(fol).iterdir()), [])
if __name__ == '__main__':
    uni2.main()
