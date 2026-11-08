# _guard_
from __future__ import annotations
import argparse as arg, ctypes as C, datetime as dat, hashlib as has2, json, os, subprocess as sub2, sys, time
from pathlib import Path
import oc as oc
root2 = Path(__file__).resolve().parents[1]
mod = ('geometry', 'texture', 'fragment')
dur = 300.0
temp_stop = 55
auth = 'gtx950-core-plus13mhz-render300s-restore-original-zero'

class Dom(C.Structure):
    _fields_ = [('present', C.c_uint32), ('value', C.c_uint32)]

class Usa(C.Structure):
    _fields_ = [('version', C.c_uint32), ('flags', C.c_uint32), ('domains', Dom * 8)]

class Fre(C.Structure):
    _fields_ = [('version', C.c_uint32), ('kind', C.c_uint32), ('domains', Dom * 32)]
assert C.sizeof(Usa) == 72 and C.sizeof(Fre) == 264

class Tel(oc.Nv):

    def __init__(self, ok_set=False):
        super().__init__(ok_set=ok_set)
        try:
            self.usage_get = self.resolve(1625215725, C.c_int32, [C.c_void_p, C.POINTER(Usa)])
            self.clocks_get = self.resolve(3702920899, C.c_int32, [C.c_void_p, C.POINTER(Fre)])
        except BaseException:
            self.close()
            raise

    def sample(self):
        usa = Usa()
        usa.version = 65608
        clks = Fre()
        clks.version = 196872
        self.check(self.usage_get(self.gpu, C.byref(usa)), 'read utilization')
        self.check(self.clocks_get(self.gpu, C.byref(clks)), 'read current frequencies')
        gpu = usa.domains[0].value if usa.domains[0].present & 1 else None
        if gpu is not None and (not 0 <= gpu <= 100):
            raise oc.OcErr('Invalid GPU utilization')
        return {'temperature_c': self.temperature(), 'gpu_utilization_percent': gpu, 'core_clock_mhz': clks.domains[0].value / 1000 if clks.domains[0].present & 1 else None, 'memory_clock_mhz': clks.domains[4].value / 1000 if clks.domains[4].present & 1 else None}
from jio import rd_json as read, ato_json as ato

def utc():
    return dat.datetime.now(dat.timezone.utc).isoformat()

def fps():
    res4 = oc.src_fps()
    for name in ['st.py', 'gl.py', 'jio.py'] + [dict(geometry='rg.py', texture='rt.py', fragment='rf.py')[m] for m in mod]:
        p = root2 / 'scripts' / name
        res4[str(p.relative_to(root2))] = has2.sha256(p.read_bytes()).hexdigest()
    return res4

def chk_live(info, base2, ctl, base_ctl, tmp2, ok_zero=False):
    dlt = oc.gfx_clk(info)['delta_khz']
    if dlt not in ((0, 13000) if ok_zero else (13000,)):
        raise oc.OcErr('Unexpected graphics offset')
    if oc.ctl_prj(info, False) != oc.ctl_prj(base2, False):
        raise oc.OcErr('Non-target clock/voltage control changed')
    oc.chk_non_tgt_ctl(ctl, base_ctl)
    if not 0 <= tmp2 < temp_stop:
        raise oc.OcErr('Conservative temperature stop condition')

def gua_rea(now, dea, hb, par_ali):
    if not par_ali:
        return 'parent exited'
    if now >= dea:
        return 'recovery deadline'
    if now - hb > 5 or hb > now + 1:
        return 'controller heartbeat stale'
    return None

def hid_ch(args, fol, name):
    out = (fol / (name + '-stdout.txt')).open('wb')
    err = (fol / (name + '-stderr.txt')).open('wb')
    try:
        ch = sub2.Popen([sys.executable, *map(str, args)], cwd=root2, stdin=sub2.DEVNULL, stdout=out, stderr=err, creationflags=sub2.CREATE_NO_WINDOW)
    finally:
        out.close()
        err.close()
    return ch

def stop_chs(chs):
    for ch in chs:
        if ch.poll() is None:
            try:
                ch.wait(tim=1)
            except sub2.TimeoutExpired:
                ch.terminate()
                ch.wait(tim=5)

def open_sup_han(plan):
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [C.c_uint32, C.c_int, C.c_uint32]
    k.OpenProcess.restype = C.c_void_p
    k.WaitForSingleObject.argtypes = [C.c_void_p, C.c_uint32]
    k.WaitForSingleObject.restype = C.c_uint32
    k.TerminateProcess.argtypes = [C.c_void_p, C.c_uint32]
    k.TerminateProcess.restype = C.c_int
    k.CloseHandle.argtypes = [C.c_void_p]
    k.CloseHandle.restype = C.c_int
    han2 = []
    try:
        par2 = k.OpenProcess(1048576, 0, plan['parent_pid'])
        if not par2:
            raise oc.OcErr('Cannot supervise parent')
        han2.append(par2)
        pids = plan['renderer_pids']
        if len(set(pids)) != 3 or any((pid in (plan['parent_pid'], os.getpid()) for pid in pids)):
            raise oc.OcErr('Invalid owned renderer list')
        for pid in pids:
            h = k.OpenProcess(1048577, 0, pid)
            if not h:
                raise oc.OcErr('Cannot supervise owned renderer')
            han2.append(h)
        return (k, han2)
    except BaseException:
        for h in han2:
            k.CloseHandle(h)
        raise

def wd(plan_pth):
    plan_pth = plan_pth.resolve()
    dir2 = plan_pth.parent
    if (root2 / 'analysis/phase10').resolve() not in dir2.parents or plan_pth.name != 'plan.json':
        raise oc.OcErr('Invalid supervisor workspace')
    plan = read(plan_pth)
    if plan.get('authorization') != auth or plan.get('duration_seconds') != dur or plan.get('original_core_khz') != 0 or (plan.get('trial_core_khz') != 13000):
        raise oc.OcErr('Invalid explicit recovery authorization')
    if not time.monotonic() < plan['recovery_deadline_monotonic'] <= time.monotonic() + 330:
        raise oc.OcErr('Invalid recovery deadline')
    k, han2 = open_sup_han(plan)
    oc.live = True
    oc.run_dir = dir2
    try:
        with Tel(ok_set=True) as api:
            if oc.ctl_prj(api.read()) != oc.ctl_prj(plan['baseline_pstates']):
                raise oc.OcErr('Baseline changed before supervisor arm')
            oc.chk_ctl(oc.rd_ctl())
            ato(dir2 / 'watchdog-ready.json', {'pid': os.getpid(), 'armed': True, 'at_utc': utc()})
            rea3 = 'unknown'
            fai = None
            smp2 = []
            try:
                while True:
                    if (dir2 / 'restored.json').exists():
                        rea3 = 'parent restore completed'
                        break
                    now = time.monotonic()
                    hb = read(dir2 / 'controller-heartbeat.json')['monotonic']
                    rea3 = gua_rea(now, plan['recovery_deadline_monotonic'], hb, k.WaitForSingleObject(han2[0], 0) == 258)
                    if rea3:
                        break
                    info = api.read()
                    tmp2 = api.temperature()
                    chk_live(info, plan['baseline_pstates'], oc.rd_ctl(), plan['baseline_macm'], tmp2, ok_zero=True)
                    smp2.append({'monotonic': time.monotonic(), 'temperature_c': tmp2, 'delta_khz': oc.gfx_clk(info)['delta_khz']})
                    time.sleep(0.5)
            except BaseException as exc:
                rea3 = 'supervisor stop condition'
                fai = str(exc)
            if rea3 != 'parent restore completed':
                ato(dir2 / 'stop-renderers.json', {'reason': rea3, 'failure': fai, 'at_utc': utc()})
                for h in han2[1:]:
                    if k.WaitForSingleObject(h, 300) == 258:
                        k.TerminateProcess(h, 2)
            rstd = oc.rst_zero(api, plan['baseline_pstates'])
            ato(dir2 / 'watchdog-result.json', {'reason': rea3, 'failure': fai, 'pid': os.getpid(), 'restore': rstd, 'temperature_samples': smp2, 'finished_at_utc': utc()})
            if not rstd['verified']:
                raise oc.OcErr('Supervisor could not verify complete restoration')
    finally:
        oc.live = False
        oc.run_dir = None
        for h in han2:
            k.CloseHandle(h)

def tri(dir2, base_dir, ack):
    if not ack:
        raise oc.OcErr('Explicit +13 MHz / 300-second render / restore-zero acknowledgment required')
    if oc.live:
        raise oc.OcErr('A write authorization is already active')
    dir2 = dir2.resolve()
    base_dir = base_dir.resolve()
    if (root2 / 'analysis/phase10').resolve() not in dir2.parents or dir2.exists():
        raise oc.OcErr('A new phase10 trial directory is required')
    if not read(base_dir / 'summary.json')['all_passed']:
        raise oc.OcErr('Stock workload references required')
    for mode in mod:
        if read(base_dir / mode / 'result.json')['status'] != 'completed':
            raise oc.OcErr('Failed stock renderer')
    dir2.mkdir(parents=True)
    chs = []
    sup = None
    fai = None
    sent = False
    rstd = None
    plan = None
    sta2 = None
    oc.live = True
    oc.run_dir = dir2
    log_file = (dir2 / 'telemetry.jsonl').open('w', encoding='utf-8')
    eve2 = []

    def eve(kind, **data):
        item = {'event': kind, 'monotonic': time.monotonic(), 'at_utc': utc(), **data}
        eve2.append(item)
        ato(dir2 / 'events.json', {'events': eve2})
        print(json.dumps(item), flush=True)
    try:
        with Tel(ok_set=True) as api:
            base2 = api.read()
            ctl = oc.rd_ctl()
            bef = api.sample()
            oc.chk_pre(base2, bef['temperature_c'])
            oc.chk_ctl(ctl)
            has = fps()
            eve('preflight_passed', identity=api.identity, telemetry=bef)
            try:
                for ind2, mode in enumerate(mod):
                    ch = hid_ch([root2 / 'scripts' / dict(geometry='rg.py', texture='rt.py', fragment='rf.py')[mode], '--directory', dir2 / mode, '--seconds', '100', '--reference', base_dir / mode / 'ready.json', '--start-file', dir2 / 'schedule.json', '--stop-file', dir2 / 'stop-renderers.json', '--phase', ind2], dir2, mode)
                    chs.append(ch)
                    dea = time.monotonic() + 15
                    while not (dir2 / mode / 'ready.json').exists():
                        if ch.poll() is not None:
                            raise oc.OcErr(f'{mode} failed before arming')
                        if time.monotonic() > dea:
                            raise oc.OcErr(f'{mode} preparation timeout')
                        oc.chk_pre(api.read(), api.temperature())
                        time.sleep(0.1)
                oc.chk_pre(api.read(), api.temperature())
                oc.chk_ctl(oc.rd_ctl())
                plan = {'authorization': auth, 'duration_seconds': dur, 'temperature_stop_c': temp_stop, 'parent_pid': os.getpid(), 'renderer_pids': [p.pid for p in chs], 'original_core_khz': 0, 'trial_core_khz': 13000, 'identity': api.identity, 'baseline_pstates': base2, 'baseline_macm': ctl, 'baseline_directory': str(base_dir), 'fingerprints': has, 'recovery_deadline_monotonic': time.monotonic() + 315, 'created_at_utc': utc()}
                ato(dir2 / 'plan.json', plan)
                ato(dir2 / 'controller-heartbeat.json', {'monotonic': time.monotonic()})
                sup = hid_ch([Path(__file__).resolve(), '_watchdog', '--plan', dir2 / 'plan.json'], dir2, 'watchdog')
                dea = time.monotonic() + 5
                while not (dir2 / 'watchdog-ready.json').exists():
                    if sup.poll() is not None or time.monotonic() > dea:
                        raise oc.OcErr('Recovery supervisor did not arm')
                    ato(dir2 / 'controller-heartbeat.json', {'monotonic': time.monotonic()})
                    time.sleep(0.1)
                oc.chk_pre(api.read(), api.temperature())
                oc.chk_ctl(oc.rd_ctl())
                eve('supervisor_armed', pid=sup.pid)
                sent = True
                api.set_core(13000)
                cur2 = api.read()
                tel = api.sample()
                chk_live(cur2, base2, oc.rd_ctl(), ctl, tel['temperature_c'])
                eve('core_offset_applied', raw_status=api.last_set_status, observed_delta_khz=oc.gfx_clk(cur2)['delta_khz'])
                sta2 = time.monotonic() + 0.1
                ato(dir2 / 'schedule.json', {'start_monotonic': sta2, 'end_monotonic': sta2 + dur, 'phase_seconds': 100, 'created_at_utc': utc()})
                next_pro = sta2
                while time.monotonic() < sta2 + dur:
                    now = time.monotonic()
                    ato(dir2 / 'controller-heartbeat.json', {'monotonic': now})
                    if sup.poll() is not None or (dir2 / 'stop-renderers.json').exists():
                        raise oc.OcErr('Recovery supervisor stopped the test')
                    cur2 = api.read()
                    tel = api.sample()
                    chk_live(cur2, base2, oc.rd_ctl(), ctl, tel['temperature_c'])
                    dt = time.monotonic() - sta2
                    pha2 = max(0, min(2, int(dt // 100)))
                    for ind2, ch in enumerate(chs):
                        rc = ch.poll()
                        if rc is not None:
                            if rc != 0 or dt < (ind2 + 1) * 100 - 0.2:
                                raise oc.OcErr(f'{mod[ind2]} exited early or with error')
                        elif ind2 == pha2 and dt - ind2 * 100 > 3:
                            hp = dir2 / mod[ind2] / 'heartbeat.json'
                            if not hp.exists() or time.monotonic() - read(hp)['monotonic'] > 3.5:
                                raise oc.OcErr('Renderer heartbeat stale')
                    row = {'monotonic': time.monotonic(), 'elapsed_seconds': dt, 'phase': mod[pha2], 'core_offset_khz': oc.gfx_clk(cur2)['delta_khz'], **tel}
                    log_file.write(json.dumps(row) + '\n')
                    log_file.flush()
                    ato(dir2 / 'controller-heartbeat.json', {'monotonic': time.monotonic()})
                    if now >= next_pro:
                        eve('progress', **row)
                        next_pro += 30
                    time.sleep(min(0.5, max(0, sta2 + dur - time.monotonic())))
                eve('scheduled_300_seconds_finished')
            except BaseException as exc:
                fai = str(exc)
                eve('test_stopped', reason=fai)
            finally:
                ato(dir2 / 'stop-renderers.json', {'reason': fai or 'scheduled completion', 'at_utc': utc()})
                rstd = oc.rst_zero(api, base2)
                if rstd['verified']:
                    ato(dir2 / 'restored.json', {'verified': True, 'at_utc': utc()})
                eve('parent_restore', verified=rstd['verified'], errors=rstd.get('errors', []))
                stop_chs(chs)
                if sup is not None:
                    try:
                        sup.wait(tim=max(8, plan['recovery_deadline_monotonic'] - time.monotonic() + 5))
                    except sub2.TimeoutExpired:
                        fai = fai or 'Recovery supervisor remains active'
                ind = read(dir2 / 'watchdog-result.json') if (dir2 / 'watchdog-result.json').exists() else None
                aft = api.read()
                aft_ctl = oc.rd_ctl()
                aft_tel = api.sample()
                wor2 = {m: read(dir2 / m / 'result.json') if (dir2 / m / 'result.json').exists() else None for m in mod}
                full = all((w and w['status'] == 'completed' and (w['elapsed_seconds'] >= 99.5) and (w['checksum_checks'] >= 90) for w in wor2.values()))
                ctls_mat = oc.ctl_prj(aft) == oc.ctl_prj(base2)
                try:
                    oc.chk_non_tgt_ctl(aft_ctl, ctl)
                except Exception as exc:
                    fai = fai or str(exc)
                if not fps() == has:
                    fai = fai or 'Tracked source/configuration changed'
                if not full:
                    fai = fai or 'Not all render phases completed 100 seconds'
                if not ctls_mat or not rstd['verified'] or (not ind) or (not ind['restore']['verified']):
                    fai = fai or 'Restoration not independently verified'
                if ind and ind['reason'] != 'parent restore completed':
                    fai = fai or ind['reason']
                res4 = {'success': fai is None, 'failure': fai, 'trial_request_sent': sent, 'original_core_khz': 0, 'requested_core_khz': 13000, 'parent_restore': rstd, 'independent_restore': ind, 'supervisor_exited': sup is not None and sup.poll() is not None, 'renderers': wor2, 'all_render_phases_completed': full, 'after_pstates': aft, 'after_control': aft_ctl, 'after_telemetry': aft_tel, 'all_pstate_controls_match_baseline': ctls_mat, 'source_fingerprints_unchanged': fps() == has, 'memory_voltage_power_thermal_fan_setters_used': False, 'finished_at_utc': utc()}
                ato(dir2 / 'result.json', res4)
                eve('test_finalized', success=res4['success'], failure=fai)
            if fai:
                raise oc.OcErr(fai)
    finally:
        log_file.close()
        oc.live = False
        oc.run_dir = None
        ato(dir2 / 'authorization-closed.json', {'live_authorization': False, 'authorization': auth, 'at_utc': utc()})
        for name in ['st.py', 'gl.py', 'jio.py'] + [dict(geometry='rg.py', texture='rt.py', fragment='rf.py')[m] for m in mod]:
            (dir2 / (name + '.txt')).write_bytes((root2 / 'scripts' / name).read_bytes())

def main():
    p = arg.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    t = sub.add_parser('trial')
    t.add_argument('--directory', type=Path, required=True)
    t.add_argument('--baseline-directory', type=Path, required=True)
    t.add_argument('--ack-core-plus13mhz-render300s-restore-zero', action='store_true')
    w = sub.add_parser('_watchdog')
    w.add_argument('--plan', type=Path, required=True)
    a = p.parse_args()
    if a.command == 'trial':
        tri(a.directory, a.baseline_directory, a.ack_core_plus13mhz_render300s_restore_zero)
    else:
        wd(a.plan)
if __name__ == '__main__':
    main()
