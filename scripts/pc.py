# _abi_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
from pathlib import Path
import struct as st2
from pp import PpErr, v_1_byt, prs
doms = {'graphics': 0, 'memory': 4}
ver = 72852
min_i_32, max_i_32 = (-(1 << 31), (1 << 31) - 1)

class PcErr(ValueError):
    pass

def _int(val, lab):
    if type(val) is not int or not min_i_32 <= val <= max_i_32:
        raise PcErr(f'{lab} must be a signed 32-bit integer')
    return val

def _dom(val):
    _int(val, 'domain')
    if val not in doms.values():
        raise PcErr('Only observed graphics (0) and memory (4) domains are supported')
    return val

def rth_boo_from_sts(raw_sts: int) -> int:
    return int(_int(raw_sts, 'raw NVAPI status') == 0)

def make_clk_req(dom: int, dlt_khz: int) -> bytes:
    _dom(dom)
    _int(dlt_khz, 'delta_khz')
    data = bytearray(v_1_byt)
    st2.pack_into('<5I', data, 0, ver, 0, 1, 1, 0)
    st2.pack_into('<I', data, 20, 0)
    st2.pack_into('<I', data, 28, dom)
    st2.pack_into('<i', data, 40, dlt_khz)
    return bytes(data)

def insp_clk_req(data: bytes) -> dict:
    if len(data) != v_1_byt:
        raise PcErr(f'A narrow V1 request must be exactly {v_1_byt} bytes')
    if st2.unpack_from('<I', data)[0] != ver:
        raise PcErr('Expected the observed V1 request version 0x11c94')
    dom = st2.unpack_from('<I', data, 28)[0]
    dlt = st2.unpack_from('<i', data, 40)[0]
    exp2 = make_clk_req(dom, dlt)
    if data != exp2:
        dir4 = [i for i, (act, wan) in enumerate(zip(data, exp2)) if act != wan]
        raise PcErr('Not a narrow clock-only request; mismatched byte offsets: ' + str(dir4[:16]))
    return {'version': hex(ver), 'bytes': len(data), 'state_id': 0, 'domain': dom, 'domain_name': next((k for k, v in doms.items() if v == dom)), 'delta_khz': dlt, 'num_states': 1, 'num_clocks': 1, 'num_base_voltages': 0, 'all_unlisted_bytes_zero': True, 'sha256': has2.sha256(data).hexdigest()}

def _sna(data: bytes) -> dict:
    try:
        val = prs(data, con='snapshot')
    except PpErr as exc:
        raise PcErr(str(exc)) from exc
    if val['trailing_bytes']:
        raise PcErr('Snapshot must contain exactly one declared PStates structure')
    _ctls(val)
    return val

def _ctls(sna: dict) -> dict:
    res4, sts = ({}, set())

    def add(key, val):
        if key in res4:
            raise PcErr('Duplicate control key in snapshot: ' + key)
        res4[key] = val
    for st in sna['states']:
        sid = st['state_id']
        if sid in sts:
            raise PcErr('Duplicate P-state ID in snapshot')
        sts.add(sid)
        for clk in st['clocks']:
            add(f"clock:P{sid}:D{clk['domain']}", clk['frequency_delta']['value'])
        for vlt in st['base_voltage_entries']:
            add(f"voltage:P{sid}:D{vlt['domain']}", vlt['voltage_delta']['value'])
    for vlt in sna['relative_voltage_entries']:
        add(f"voltage:OV:D{vlt['domain']}", vlt['voltage_delta']['value'])
    return res4

def _vlt_md(sna: dict) -> dict:
    res4 = {}
    for st in sna['states']:
        for vlt in st['base_voltage_entries']:
            res4[f"voltage:P{st['state_id']}:D{vlt['domain']}"] = vlt['reported_base_voltage_uv']
    for vlt in sna['relative_voltage_entries']:
        res4[f"voltage:OV:D{vlt['domain']}"] = vlt['reported_base_voltage_uv']
    return res4

def _tgt(sna: dict, dom: int):
    st = next((s for s in sna['states'] if s['state_id'] == 0), None)
    if st is None:
        raise PcErr('P0 is absent from the provided snapshot')
    clk = next((c for c in st['clocks'] if c['domain'] == dom), None)
    if clk is None:
        raise PcErr('Requested clock domain is absent from P0')
    return (st, clk)

def _diff(bef: dict, aft: dict, exc2=()) -> list:
    return [{'key': key, 'before': bef.get(key), 'after': aft.get(key), 'before_present': key in bef, 'after_present': key in aft} for key in sorted(set(bef) | set(aft)) if key not in exc2 and (key not in bef or key not in aft or bef[key] != aft[key])]

def plan_clk_cha(sna_data: bytes, dom: int, dlt_khz: int) -> dict:
    _dom(dom)
    _int(dlt_khz, 'delta_khz')
    sna = _sna(sna_data)
    st, clk = _tgt(sna, dom)
    for lab, obj in [('info', sna), ('P0', st), ('clock', clk)]:
        if not obj['editable']:
            raise PcErr(lab + ' is not marked editable in this snapshot')
        if obj['reserved_flag_bits']:
            raise PcErr(lab + ' has unknown reserved flag bits')
    if clk['type_id'] not in (0, 1):
        raise PcErr('Unrecognized clock union type')
    lim = clk['frequency_delta']
    if not lim['range_ordered']:
        raise PcErr('Snapshot reports an inverted frequency-delta range')
    if not lim['minimum'] <= dlt_khz <= lim['maximum']:
        raise PcErr('Requested delta is outside the range in the supplied snapshot')
    req2 = make_clk_req(dom, dlt_khz)
    rst = make_clk_req(dom, lim['value'])
    return {'mode': 'offline clock-change plan', 'hardware_writes': False, 'invocation_available': False, 'gpu_identity_verified': False, 'snapshot_sha256': has2.sha256(sna_data).hexdigest(), 'offline_contract_checks_passed': True, 'reported_range_khz': {'minimum': lim['minimum'], 'maximum': lim['maximum']}, 'previous_delta_khz': lim['value'], 'request': insp_clk_req(req2), 'restore_original': insp_clk_req(rst), 'limits': ['A historical or synthetic snapshot is not a live capability check.', 'GPU identity, driver version, timestamps and handle association are external to this ABI.', 'Reported bounds do not establish stability or safe operation.', 'The restore request is data only, is not executed, and is not guaranteed to succeed.', 'No voltage, power, fan, thermal or VF-curve writes are implemented.']}

def cmp_clk_rea(bef_data: bytes, aft_data: bytes, dom: int, dlt_khz: int) -> dict:
    _dom(dom)
    _int(dlt_khz, 'delta_khz')
    bef, aft = (_sna(bef_data), _sna(aft_data))
    _tgt(bef, dom)
    key = f'clock:P0:D{dom}'
    base2, obs = (_ctls(bef), _ctls(aft))
    tgt_mat = obs.get(key) == dlt_khz and key in obs
    cha3 = _diff(base2, obs, exc2=(key,))
    md = _diff(_vlt_md(bef), _vlt_md(aft))
    return {'mode': 'offline control-field comparison', 'hardware_writes': False, 'gpu_identity_verified': False, 'transport_status_verified': False, 'control_fields_match': tgt_mat and (not cha3), 'target': {'key': key, 'before_delta_khz': base2[key], 'requested_delta_khz': dlt_khz, 'observed_delta_khz': obs.get(key), 'present': key in obs, 'matches_requested': tgt_mat}, 'unexpected_control_changes': cha3, 'reported_voltage_metadata_changes': md, 'limits': ['This compares supplied snapshots only; it does not prove a setter was invoked.', 'No GPU identity or timestamp is embedded in these packets.', 'Base-voltage metadata changes are reported separately from voltage-delta controls.', 'No conclusion about physical voltage constancy, performance or stability follows.']}

def _rd(path: Path) -> bytes:
    if path.stat().st_size > 65536:
        raise PcErr('Input exceeds the 64 KiB packet analysis limit')
    return path.read_bytes()

def main():
    ap = arg.ArgumentParser(description=__doc__)
    com2 = ap.add_subparsers(dest='command', required=True)
    for name in ('request', 'plan', 'compare'):
        sub = com2.add_parser(name)
        sub.add_argument('--domain', choices=doms, required=True)
        sub.add_argument('--delta-khz', type=int, required=True)
        if name == 'request':
            sub.add_argument('--out', type=Path, help='Write an offline packet to a new file; never overwrite')
        elif name == 'plan':
            sub.add_argument('snapshot', type=Path)
        else:
            sub.add_argument('before', type=Path)
            sub.add_argument('after', type=Path)
    args = ap.parse_args()
    try:
        dom = doms[args.domain]
        if args.command == 'request':
            data = make_clk_req(dom, args.delta_khz)
            res4 = {'mode': 'offline request construction; not submitted', 'hardware_writes': False, 'invocation_available': False, 'request': insp_clk_req(data)}
            if args.out is not None:
                with args.out.open('xb') as file:
                    file.write(data)
                res4['file'] = str(args.out)
        elif args.command == 'plan':
            res4 = plan_clk_cha(_rd(args.snapshot), dom, args.delta_khz)
        else:
            res4 = cmp_clk_rea(_rd(args.before), _rd(args.after), dom, args.delta_khz)
        print(json.dumps(res4, indent=2))
        if args.command == 'compare' and (not res4['control_fields_match']):
            ap.exit(1)
    except (PcErr, OSError) as exc:
        ap.exit(2, f'Error: {exc}\n')
if __name__ == '__main__':
    main()
