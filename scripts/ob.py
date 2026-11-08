# _guard_
from __future__ import annotations
import argparse as arg
import ctypes as C
from ctypes import wintypes as W
import hashlib as has2
import json
import os
from pathlib import Path
import subprocess as sub2
import sys
import time
root2 = Path(__file__).resolve().parents[1]
gpu_nm = 'NVIDIA GeForce GTX 950'
dev_id = 335679710
sub_id = 596122074
bus_id = 1
d_khz = 13000
hold_sec = 8.0
max_tmp = 55
live = False
ps_get = 1878528531
ps_set = 256749163
life = {'init': 22079528, 'unload': 3526090110}

class OcErr(RuntimeError):
    pass

class Dlt(C.Structure):
    _fields_ = [('value', C.c_int32), ('minimum', C.c_int32), ('maximum', C.c_int32)]

class Clk(C.Structure):
    _fields_ = [('domain', C.c_uint32), ('type_id', C.c_uint32), ('editable', C.c_uint32), ('delta', Dlt), ('data', C.c_uint32 * 5)]

class Vlt(C.Structure):
    _fields_ = [('domain', C.c_uint32), ('editable', C.c_uint32), ('microvolts', C.c_uint32), ('delta', Dlt)]

class Pst(C.Structure):
    _fields_ = [('state_id', C.c_uint32), ('editable', C.c_uint32), ('clocks', Clk * 8), ('voltages', Vlt * 4)]

class Ps(C.Structure):
    _fields_ = [('version', C.c_uint32), ('editable', C.c_uint32), ('num_states', C.c_uint32), ('num_clocks', C.c_uint32), ('num_voltages', C.c_uint32), ('states', Pst * 16)]

class Sen(C.Structure):
    _fields_ = [('controller', C.c_int32), ('min_c', C.c_int32), ('max_c', C.c_int32), ('current_c', C.c_int32), ('target', C.c_int32)]

class Thm(C.Structure):
    _fields_ = [('version', C.c_uint32), ('count', C.c_uint32), ('sensors', Sen * 3)]
assert C.sizeof(Dlt) == 12 and C.sizeof(Clk) == 44 and (C.sizeof(Vlt) == 24)
assert C.sizeof(Pst) == 456 and C.sizeof(Ps) == 7316
assert Pst.clocks.offset == 8 and Clk.delta.offset == 12
assert C.sizeof(Thm) == 68

def make_req(dlt_khz: int) -> Ps:
    if dlt_khz not in (0, d_khz):
        raise OcErr('Only zero-baseline restore or +13 MHz is permitted')
    req2 = Ps()
    req2.version = 72852
    req2.num_states = 1
    req2.num_clocks = 1
    req2.num_voltages = 0
    req2.states[0].state_id = 0
    req2.states[0].clocks[0].domain = 0
    req2.states[0].clocks[0].delta.value = dlt_khz
    return req2

def ato_json(path: Path, val: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + str(os.getpid()) + '.tmp')
    temp.write_text(json.dumps(val, indent=2) + '\n', encoding='utf-8')
    os.replace(temp, path)

def pub_ps(info: Ps) -> dict:
    if info.num_states > 16 or info.num_clocks > 8 or info.num_voltages > 4:
        raise OcErr('Out-of-range PStates count returned')
    sts = []
    for st in info.states[:info.num_states]:
        sts.append({'id': st.state_id, 'editable': bool(st.editable & 1), 'clocks': [{'domain': clk.domain, 'type': clk.type_id, 'editable': bool(clk.editable & 1), 'delta_khz': clk.delta.value, 'min_khz': clk.delta.minimum, 'max_khz': clk.delta.maximum, 'clock_data': list(clk.data)} for clk in st.clocks[:info.num_clocks]], 'voltages': [{'domain': v.domain, 'microvolts': v.microvolts, 'delta_uv': v.delta.value, 'min_delta_uv': v.delta.minimum, 'max_delta_uv': v.delta.maximum} for v in st.voltages[:info.num_voltages]]})
    return {'editable': bool(info.editable & 1), 'states': sts}

def gfx_clk(info: dict) -> dict:
    p0 = [st for st in info['states'] if st['id'] == 0]
    if len(p0) != 1:
        raise OcErr('Expected one P0 state')
    core = [clk for clk in p0[0]['clocks'] if clk['domain'] == 0]
    if len(core) != 1:
        raise OcErr('Expected one graphics clock in P0')
    return core[0]

def ctl_prj(info: dict, inc_core=True) -> dict:
    res4 = {}
    for st in info['states']:
        for clk in st['clocks']:
            if inc_core or not (st['id'] == 0 and clk['domain'] == 0):
                res4[f"p{st['id']}/clock/{clk['domain']}"] = clk['delta_khz']
        for vlt in st['voltages']:
            res4[f"p{st['id']}/voltage/{vlt['domain']}"] = {'delta_uv': vlt['delta_uv']}
    return res4

def vlt_md(info: dict) -> dict:
    return {f"p{st['id']}/voltage/{v['domain']}": v['microvolts'] for st in info['states'] for v in st['voltages']}

class Nv:

    def __init__(self, ok_set=False):
        if ok_set and (not live):
            raise OcErr('Live setter is locked after the completed debug trial')
        if os.name != 'nt':
            raise OcErr('Windows-only live inspection')
        name = 'nvapi64.dll' if C.sizeof(C.c_void_p) == 8 else 'nvapi.dll'
        self.dll = C.CDLL(name, winmode=2048)
        self.query = self.dll.nvapi_QueryInterface
        self.query.argtypes = [C.c_uint32]
        self.query.restype = C.c_void_p
        self.init = self.resolve(life['init'], C.c_int32, [])
        self.unload = self.resolve(life['unload'], C.c_int32, [])
        self.check(self.init(), 'initialize')
        self.active = True
        enum = self.resolve(3853292063, C.c_int32, [C.POINTER(C.c_void_p), C.POINTER(C.c_uint32)])
        han2 = (C.c_void_p * 64)()
        cou = C.c_uint32()
        self.check(enum(han2, C.byref(cou)), 'enumerate')
        if cou.value != 1:
            raise OcErr('Trial requires exactly one NVIDIA physical GPU')
        self.gpu = han2[0]
        full_name = self.resolve(3471740575, C.c_int32, [C.c_void_p, C.c_void_p])
        text = C.create_string_buffer(64)
        self.check(full_name(self.gpu, text), 'name')
        pci = self.resolve(769635950, C.c_int32, [C.c_void_p] + [C.POINTER(C.c_uint32)] * 4)
        d, s, r, e = [C.c_uint32() for _ in range(4)]
        self.check(pci(self.gpu, C.byref(d), C.byref(s), C.byref(r), C.byref(e)), 'PCI identifiers')
        bus_get = self.resolve(467712229, C.c_int32, [C.c_void_p, C.POINTER(C.c_uint32)])
        bus = C.c_uint32()
        self.check(bus_get(self.gpu, C.byref(bus)), 'PCI bus')
        self.identity = {'name': text.value.decode('ascii', 'replace'), 'device_id': hex(d.value), 'subsystem_id': hex(s.value), 'revision': hex(r.value), 'bus': bus.value}
        if self.identity['name'] != gpu_nm or d.value != dev_id or s.value != sub_id or (bus.value != bus_id):
            raise OcErr('GPU identity differs from authorized GTX 950 fixture: ' + str(self.identity))
        self.get = self.resolve(ps_get, C.c_int32, [C.c_void_p, C.POINTER(Ps)])
        self.thermal = self.resolve(3814984278, C.c_int32, [C.c_void_p, C.c_uint32, C.POINTER(Thm)])
        self.setter = self.resolve(ps_set, C.c_int32, [C.c_void_p, C.POINTER(Ps)]) if ok_set else None

    def resolve(self, sel2, res3, arg2):
        addr2 = self.query(sel2)
        if not addr2:
            raise OcErr(f'NVAPI selector unavailable: {sel2:#x}')
        return C.CFUNCTYPE(res3, *arg2)(addr2)

    @staticmethod
    def check(sts2, ope3):
        if sts2 != 0:
            raise OcErr(f'{ope3}: NVAPI status {sts2}')

    def read(self):
        info = Ps()
        info.version = 72852
        self.check(self.get(self.gpu, C.byref(info)), 'GetPstates20 v1')
        return pub_ps(info)

    def temperature(self):
        info = Thm()
        info.version = 131140
        self.check(self.thermal(self.gpu, 15, C.byref(info)), 'thermal')
        if info.count > 3:
            raise OcErr('Invalid thermal count')
        core = [v.current_c for v in info.sensors[:info.count] if v.target == 1]
        if not core:
            raise OcErr('GPU temperature unavailable')
        return max(core)

    def set_core(self, dlt_khz):
        if self.setter is None:
            raise OcErr('Setter not enabled in inspect mode')
        req2 = make_req(dlt_khz)
        self.check(self.setter(self.gpu, C.byref(req2)), 'SetPstates20 graphics delta')

    def close(self):
        if getattr(self, 'active', False):
            self.unload()
            self.active = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

def insp(out: Path):
    with Nv() as api:
        info = api.read()
        res4 = {'mode': 'read-only inspection', 'identity': api.identity, 'pstates': info, 'temperature_c': api.temperature(), 'structure_bytes': C.sizeof(Ps), 'graphics': gfx_clk(info), 'hardware_writes': False}
        ato_json(out, res4)
        print(json.dumps(res4, indent=2))

def rd_ctl() -> dict:
    if os.name != 'nt':
        raise OcErr('Windows-only mapping')
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenFileMappingW.argtypes = [W.DWORD, W.BOOL, W.LPCWSTR]
    k.OpenFileMappingW.restype = W.HANDLE
    k.MapViewOfFile.argtypes = [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, C.c_size_t]
    k.MapViewOfFile.restype = C.c_void_p
    k.UnmapViewOfFile.argtypes = [C.c_void_p]
    k.UnmapViewOfFile.restype = W.BOOL
    k.CloseHandle.argtypes = [W.HANDLE]
    k.CloseHandle.restype = W.BOOL
    han = k.OpenFileMappingW(4, False, 'MACMSharedMemory')
    if not han:
        raise OcErr('MACM mapping unavailable')
    vie = []
    try:
        view = k.MapViewOfFile(han, 4, 0, 0, 36)
        if not view:
            raise OcErr('Cannot map MACM header')
        vie.append(view)
        import struct as st2
        fir = C.string_at(view, 36)
        h = st2.unpack('<9I', fir)
        if h[0] != 1296122701 or h[1] != 131075 or h[2] != 36 or (h[3] != 1) or (h[4] != 3760) or (h[5] != 0):
            raise OcErr('MACM layout, GPU count or master differs from verified sample')
        view = k.MapViewOfFile(han, 4, 0, 0, 3796)
        if not view:
            raise OcErr('Cannot map control record')
        vie.append(view)
        data = C.string_at(view, 3796)
        if data[:36] != fir or C.string_at(view, 36) != fir:
            raise OcErr('Concurrent MACM update')
        u = lambda off: st2.unpack_from('<I', data, 36 + off)[0]
        i = lambda off: st2.unpack_from('<i', data, 36 + off)[0]
        idn = data[36 + 3500:36 + 3760].split(b'\x00', 1)[0].decode('ascii', 'strict')
        res4 = {'gpu_id': idn, 'flags': h[6], 'pending_command': h[8], 'capabilities': u(0), 'core_offset_khz': i(188), 'memory_offset_khz': i(204), 'power_limit_percent': i(172), 'thermal_limit_c': i(220), 'fan_mode': u(56), 'fan_speed_percent': u(52), 'voltage_control_supported': bool(u(0) & 16), 'voltage_offset_supported': bool(u(0) & 128)}
        return res4
    finally:
        for view in vie:
            k.UnmapViewOfFile(view)
        k.CloseHandle(han)

# _guard_
def chk_ctl(info: dict):
    exp2 = 'VEN_10DE&DEV_1402&SUBSYS_238819DA&REV_A1&BUS_1&DEV_0&FN_0'
    if info['gpu_id'] != exp2 or info['pending_command'] != 0:
        raise OcErr('MACM GPU mismatch or pending external command')
    if info['core_offset_khz'] != 0 or info['memory_offset_khz'] != 0:
        raise OcErr('Require zero core and memory baseline offsets')
    if info['power_limit_percent'] != 100 or info['thermal_limit_c'] != 80 or info['fan_mode'] != 1:
        raise OcErr('Unexpected baseline power/thermal/fan settings')
    if info['voltage_control_supported'] or info['voltage_offset_supported']:
        raise OcErr('This debug run does not allow unlocked voltage control')
    if not info['capabilities'] & 2048:
        raise OcErr('Core offset capability missing')

# _guard_
def chk_pre(info: dict, tmp2: int):
    gfx = gfx_clk(info)
    if not info['editable'] or not gfx['editable']:
        raise OcErr('P0 graphics delta not editable')
    if gfx['delta_khz'] != 0:
        raise OcErr('Require zero original graphics delta')
    if not gfx['min_khz'] <= 0 < d_khz <= gfx['max_khz']:
        raise OcErr('Trial delta is outside current vendor range')
    if tmp2 < 0 or tmp2 >= max_tmp:
        raise OcErr('Temperature gate failed')
    for st in info['states']:
        for clk in st['clocks']:
            if clk['delta_khz'] != 0:
                raise OcErr('Existing clock delta must not be overwritten')
        for v in st['voltages']:
            if v['delta_uv'] != 0:
                raise OcErr('Existing voltage delta must not be changed')

def src_fps() -> dict:
    pths = [root2 / 'afterb/MSI Afterburner/MSIAfterburner.exe', root2 / 'afterb/MSI Afterburner/RTHAL.dll', root2 / 'afterb/MSI Afterburner/Profiles/VEN_10DE&DEV_1402&SUBSYS_238819DA&REV_A1&BUS_1&DEV_0&FN_0.cfg']
    return {str(path.relative_to(root2)): has2.sha256(path.read_bytes()).hexdigest() for path in pths}

# _restore_
def rst_zero(api: Nv, base2: dict) -> dict:
    if gfx_clk(base2)['delta_khz'] != 0:
        raise OcErr('Zero recovery cannot replace a nonzero original offset')
    errs = []
    wrs = 0
    for att in range(3):
        try:
            cur2 = api.read()
            if ctl_prj(cur2) == ctl_prj(base2):
                return {'verified': True, 'writes': wrs, 'pstates': cur2, 'errors': errs, 'reported_voltage_metadata': vlt_md(cur2)}
            dlt = gfx_clk(cur2)['delta_khz']
            if dlt not in (0, d_khz):
                raise OcErr('Unexpected external graphics offset; no automatic overwrite')
            if dlt != 0:
                api.set_core(0)
                wrs += 1
            time.sleep(0.4)
            cur2 = api.read()
            if ctl_prj(cur2) == ctl_prj(base2):
                return {'verified': True, 'writes': wrs, 'pstates': cur2, 'errors': errs, 'reported_voltage_metadata': vlt_md(cur2)}
            errs.append('Clock or voltage offsets still differ from captured baseline')
        except Exception as exc:
            errs.append(str(exc))
            time.sleep(0.4)
    return {'verified': False, 'writes': wrs, 'errors': errs}

def wd(plan_pth: Path):
    plan = json.loads(plan_pth.read_text(encoding='utf-8'))
    if plan.get('original_core_khz') != 0 or plan.get('trial_core_khz') != d_khz:
        raise OcErr('Invalid recovery plan')
    if not time.monotonic() <= plan['recovery_deadline_monotonic'] <= time.monotonic() + 25:
        raise OcErr('Invalid recovery deadline')
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k.OpenProcess.restype = W.HANDLE
    k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    k.WaitForSingleObject.restype = W.DWORD
    k.CloseHandle.argtypes = [W.HANDLE]
    k.CloseHandle.restype = W.BOOL
    par2 = k.OpenProcess(1048576, False, plan['parent_pid'])
    if not par2:
        raise OcErr('Cannot supervise parent process')
    rea2 = Path(plan['ready_file'])
    done = Path(plan['done_file'])
    res_pth = Path(plan['watchdog_result'])
    try:
        with Nv(ok_set=True) as api:
            base2 = plan['baseline_pstates']
            if ctl_prj(api.read()) != ctl_prj(base2):
                raise OcErr('Baseline changed before watchdog arm')
            ato_json(rea2, {'pid': os.getpid(), 'armed': True, 'deadline': plan['recovery_deadline_monotonic']})
            rea3 = 'deadline'
            while time.monotonic() < plan['recovery_deadline_monotonic']:
                if done.exists():
                    rea3 = 'parent restore completed'
                    break
                if k.WaitForSingleObject(par2, 0) == 0:
                    rea3 = 'parent exited'
                    break
                time.sleep(0.15)
            rstd = rst_zero(api, base2)
            ato_json(res_pth, {'reason': rea3, 'restore': rstd, 'pid': os.getpid()})
            if not rstd['verified']:
                raise OcErr('Independent restore verification failed')
    finally:
        k.CloseHandle(par2)

def tri(dir2: Path, ack: bool):
    if not live:
        raise OcErr('Additional live trials are locked; inspect/offline audit only')
    if not ack:
        raise OcErr('Explicit +13 MHz / maximum 8 second / restore-zero acknowledgment required')
    dir2 = dir2.resolve()
    all2 = (root2 / 'analysis/phase5').resolve()
    if dir2 == all2 or all2 not in dir2.parents:
        raise OcErr('Trial logs must be in a new analysis/phase5 subdirectory')
    dir2.mkdir(parents=True, exist_ok=False)
    eve2 = []

    def log(eve, **data):
        eve2.append({'event': eve, 'monotonic': time.monotonic(), **data})
        ato_json(dir2 / 'events.json', {'events': eve2})
        print(eve, json.dumps(data), flush=True)
    log('preparing', target_core_khz=d_khz, max_hold_seconds=hold_sec)
    fps = src_fps()
    with Nv(ok_set=True) as api:
        base2 = api.read()
        tmp2 = api.temperature()
        ctl = rd_ctl()
        chk_pre(base2, tmp2)
        chk_ctl(ctl)
        rea2 = dir2 / 'watchdog-ready.json'
        done = dir2 / 'restored.json'
        wat_res = dir2 / 'watchdog-result.json'
        plan = {'parent_pid': os.getpid(), 'original_core_khz': 0, 'trial_core_khz': d_khz, 'recovery_deadline_monotonic': time.monotonic() + 20.0, 'identity': api.identity, 'baseline_pstates': base2, 'baseline_macm': ctl, 'temperature_before_c': tmp2, 'ready_file': str(rea2), 'done_file': str(done), 'watchdog_result': str(wat_res), 'fingerprints': fps}
        ato_json(dir2 / 'plan.json', plan)
        sta4 = sub2.STARTUPINFO()
        sta4.dwFlags |= sub2.STARTF_USESHOWWINDOW
        sta4.wShowWindow = 0
        std = (dir2 / 'watchdog-stderr.txt').open('wb')
        std2 = (dir2 / 'watchdog-stdout.txt').open('wb')
        ch = sub2.Popen([sys.executable, str(Path(__file__).resolve()), '_watchdog', '--plan', str(dir2 / 'plan.json')], cwd=str(root2), stdin=sub2.DEVNULL, stdout=std2, stderr=std, startupinfo=sta4, creationflags=sub2.CREATE_NO_WINDOW)
        wro = False
        rstd = None
        fai = None
        try:
            dea = time.monotonic() + 5
            while not rea2.exists() and time.monotonic() < dea:
                if ch.poll() is not None:
                    raise OcErr('Recovery process exited before arming')
                time.sleep(0.1)
            if not rea2.exists() or ch.poll() is not None:
                raise OcErr('Recovery guard not ready')
            chk_pre(api.read(), api.temperature())
            chk_ctl(rd_ctl())
            log('independent_recovery_armed', pid=ch.pid)
            wro = True
            api.set_core(d_khz)
            sta2 = time.monotonic()
            cur2 = api.read()
            dlt = gfx_clk(cur2)['delta_khz']
            log('core_request_returned', observed_delta_khz=dlt, temperature_c=api.temperature())
            if dlt != d_khz:
                raise OcErr('Requested graphics delta did not match driver readback')
            if ctl_prj(cur2, False) != ctl_prj(base2, False):
                raise OcErr('Memory or voltage control changed; restore immediately')
            while time.monotonic() - sta2 < hold_sec:
                time.sleep(min(0.8, max(0.0, hold_sec - (time.monotonic() - sta2))))
                cur2 = api.read()
                tmp2 = api.temperature()
                log('sample', elapsed_seconds=time.monotonic() - sta2, observed_delta_khz=gfx_clk(cur2)['delta_khz'], temperature_c=tmp2)
                if ch.poll() is not None:
                    raise OcErr('Recovery supervisor exited during hold')
                if tmp2 >= max_tmp or tmp2 < 0:
                    raise OcErr('Temperature gate reached')
                if gfx_clk(cur2)['delta_khz'] != d_khz:
                    raise OcErr('Driver delta changed unexpectedly')
                if ctl_prj(cur2, False) != ctl_prj(base2, False):
                    raise OcErr('Unexpected non-graphics control change')
        except BaseException as exc:
            fai = str(exc)
            log('trial_aborted', reason=fai)
        finally:
            rstd = rst_zero(api, base2)
            if rstd['verified']:
                ato_json(done, {'verified': True, 'pstates': rstd['pstates']})
            log('parent_restore', verified=rstd['verified'], errors=rstd.get('errors', []))
            try:
                ch.wait(tim=max(2, plan['recovery_deadline_monotonic'] - time.monotonic() + 5))
            except sub2.TimeoutExpired:
                log('watchdog_still_running', pid=ch.pid)
            std2.close()
            std.close()
            ind = json.loads(wat_res.read_text()) if wat_res.exists() else None
            aft_ctl = rd_ctl()
            fin = {'trial_request_sent': wro, 'failure': fai, 'original_core_khz': 0, 'trial_core_khz': d_khz, 'parent_restore': rstd, 'independent_restore': ind, 'after_control': aft_ctl, 'source_fingerprints_unchanged': src_fps() == fps, 'voltage_memory_power_thermal_fan_setters_used': False, 'stress_test_started': False}
            ato_json(dir2 / 'result.json', fin)
            if not rstd['verified'] or not ind or (not ind['restore']['verified']):
                raise OcErr('Restoration is not fully independently verified; see logs')
            log('trial_finished', restored_and_independently_verified=True)
            if fai:
                raise OcErr('Trial stopped and baseline restored: ' + fai)

def main():
    ap = arg.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='command', required=True)
    p = sub.add_parser('inspect')
    p.add_argument('--out', type=Path, required=True)
    p = sub.add_parser('trial')
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--ack-core-plus13mhz-max8s-restore-zero', action='store_true')
    p = sub.add_parser('_watchdog')
    p.add_argument('--plan', type=Path, required=True)
    args = ap.parse_args()
    if args.command == 'inspect':
        insp(args.out)
    elif args.command == 'trial':
        tri(args.directory, args.ack_core_plus13mhz_max8s_restore_zero)
    else:
        wd(args.plan)
if __name__ == '__main__':
    main()
