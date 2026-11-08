# _test_
import copy, ctypes as C, json, tempfile as tem, unittest as uni2
from pathlib import Path
from unittest.mock import patch as pat2
import st as soak
import gl as rnd
import oc as oc
from t_oc import fx, ctl

class SoakTes(uni2.TestCase):

    def test_rea_tel_lay(self):
        self.assertEqual(C.sizeof(soak.Usa), 72)
        self.assertEqual(C.sizeof(soak.Fre), 264)

    def test_exp_ack_pre_acc(self):
        with pat2.object(soak, 'Tel') as api:
            with self.assertRaises(oc.OcErr):
                soak.tri(Path('NONE'), Path('NONE'), False)
            api.assert_not_called()

    def test_pre_tri_lim_rem_unc(self):
        self.assertEqual(oc.hold_sec, 3)
        self.assertFalse(oc.live)
        self.assertEqual(soak.dur, 300)
        self.assertEqual(soak.temp_stop, 55)

    def test_hea_hea(self):
        self.assertIsNone(soak.gua_rea(10, 20, 9, True))

    def test_par_exi_tri_rec(self):
        self.assertEqual(soak.gua_rea(10, 20, 9, False), 'parent exited')

    def test_sta_hea_tri_rec(self):
        self.assertEqual(soak.gua_rea(10, 20, 4, True), 'controller heartbeat stale')

    def test_dea_tri_rec(self):
        self.assertEqual(soak.gua_rea(20, 20, 19, True), 'recovery deadline')

    def test_fut_hea_rej(self):
        self.assertEqual(soak.gua_rea(10, 20, 12, True), 'controller heartbeat stale')

    def test_liv_req_exa_cor_off(self):
        base = fx()
        now = copy.deepcopy(base)
        now['states'][0]['clocks'][0]['delta_khz'] = 13000
        with pat2.object(oc, 'chk_pro'):
            soak.chk_live(now, base, ctl(), ctl(), 24)
            with self.assertRaises(oc.OcErr):
                soak.chk_live(base, base, ctl(), ctl(), 24)
            soak.chk_live(base, base, ctl(), ctl(), 24, True)

    def test_tem_and_ov_cha_abo(self):
        base = fx()
        now = copy.deepcopy(base)
        now['states'][0]['clocks'][0]['delta_khz'] = 13000
        with pat2.object(oc, 'chk_pro'):
            for temp in [-1, 55, 90]:
                with self.assertRaises(oc.OcErr):
                    soak.chk_live(now, base, ctl(), ctl(), temp)
            now['relative_voltages'][0]['delta_uv'] = 1000
            with self.assertRaises(oc.OcErr):
                soak.chk_live(now, base, ctl(), ctl(), 24)

    def test_wor_bou_and_dis(self):
        self.assertEqual(rnd.FPS, 60)
        self.assertEqual((rnd.wid, rnd.hei), (1280, 720))
        self.assertEqual(set(rnd.fra), set(soak.mod))
        self.assertEqual(len(set(rnd.fra.values())), 3)
        self.assertEqual(C.sizeof(rnd.Pfd), 40)

    def test_fau_aft_fak_app_res_bef_exi(self):

        class FakeApi:

            def __init__(self):
                self.info = fx()
                self.identity = {'name': 'fake'}
                self.writes = []
                self.last_set_status = 0

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def read(self):
                return copy.deepcopy(self.info)

            def temperature(self):
                return 24

            def sample(self):
                if self.info['states'][0]['clocks'][0]['delta_khz'] == 13000:
                    raise oc.OcErr('injected telemetry fault')
                return {'temperature_c': 24}

            def set_core(self, v):
                self.writes.append(v)
                self.info['states'][0]['clocks'][0]['delta_khz'] = v

        class Ch:

            def __init__(self, pid):
                self.pid = pid
                self.rc = None

            def poll(self):
                return self.rc

            def wait(self, tim=None):
                self.rc = 0
                return 0
        api = FakeApi()
        with tem.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scr2 = root / 'scripts'
            scr2.mkdir()
            for name in ['st.py', 'gl.py', 'jio.py'] + [dict(geometry='rg.py', texture='rt.py', fragment='rf.py')[m] for m in soak.mod]:
                (scr2 / name).write_text('# offline fixture')
            base2 = root / 'baseline'
            base2.mkdir()
            oc.ato_json(base2 / 'summary.json', {'all_passed': True})
            for mode in soak.mod:
                oc.ato_json(base2 / mode / 'result.json', {'status': 'completed'})
            dest = root / 'analysis/phase10/injected-failure'
            chs = []

            def hid(args, fol, name):
                ch = Ch(len(chs) + 1000)
                chs.append(ch)
                if name == 'watchdog':
                    oc.ato_json(fol / 'watchdog-ready.json', {'armed': True})
                else:
                    oc.ato_json(fol / name / 'ready.json', {'ready': True})
                    oc.ato_json(fol / name / 'result.json', {'status': 'completed', 'elapsed_seconds': 100, 'checksum_checks': 100})
                return ch

            def stop(chs):
                for c in chs:
                    c.rc = 0
                oc.ato_json(dest / 'watchdog-result.json', {'reason': 'parent restore completed', 'restore': {'verified': oc.gfx_clk(api.read())['delta_khz'] == 0}})
            with pat2.object(soak, 'root2', root), pat2.object(soak, 'Tel', return_value=api), pat2.object(soak, 'hid_ch', side_effect=hid), pat2.object(soak, 'stop_chs', side_effect=stop), pat2.object(soak, 'fps', return_value={'fixture': 'unchanged'}), pat2.object(oc, 'rd_ctl', side_effect=ctl), pat2.object(oc, 'chk_pro'), pat2.object(oc.time, 'sleep'):
                with self.assertRaisesRegex(oc.OcErr, 'injected telemetry fault'):
                    soak.tri(dest, base2, True)
            self.assertEqual(api.writes, [13000, 0])
            self.assertFalse(oc.live)
            self.assertIsNone(oc.run_dir)
            res4 = json.loads((dest / 'result.json').read_text())
            self.assertFalse(res4['success'])
            self.assertTrue(res4['parent_restore']['verified'])
            self.assertFalse(json.loads((dest / 'authorization-closed.json').read_text())['live_authorization'])
if __name__ == '__main__':
    uni2.main()
