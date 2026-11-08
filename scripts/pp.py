# _abi_
from __future__ import annotations
import argparse as arg
import json
from pathlib import Path
import struct as st2
hea_byt = 20
st_byt = 456
clk_byt = 44
vlt_byt = 24
max_sts = 16
max_clks = 8
max_vlts = 4
v_1_byt = 7316
v_2_byt = 7416
ver2 = {72852: ('V1', v_1_byt), 138488: ('V2', v_2_byt), 204024: ('V3', v_2_byt)}
dom_nam = {0: 'graphics', 4: 'memory', 7: 'processor', 8: 'video', 32: 'undefined'}

class PpErr(ValueError):
    pass

def _u32(data: bytes, off2: int) -> int:
    return st2.unpack_from('<I', data, off2)[0]

def _dlt(data: bytes, off2: int, uni: str) -> dict:
    val, min2, max2 = st2.unpack_from('<3i', data, off2)
    return {'value': val, 'minimum': min2, 'maximum': max2, 'units': uni, 'range_ordered': min2 <= max2}

def _clk(data: bytes, off2: int) -> dict:
    dom, kind, fla = st2.unpack_from('<3I', data, off2)
    raw = list(st2.unpack_from('<5I', data, off2 + 24))
    if kind == 0:
        det = {'type': 'single', 'frequency_khz': raw[0]}
    elif kind == 1:
        det = {'type': 'range', 'minimum_frequency_khz': raw[0], 'maximum_frequency_khz': raw[1], 'voltage_domain': raw[2], 'minimum_voltage_uv': raw[3], 'maximum_voltage_uv': raw[4]}
    else:
        det = {'type': 'unrecognized', 'raw_dwords': raw}
    return {'byte_offset': off2, 'domain': dom, 'domain_name': dom_nam.get(dom, 'unrecognized'), 'type_id': kind, 'editable': bool(fla & 1), 'reserved_flag_bits': fla & 4294967294, 'frequency_delta': _dlt(data, off2 + 12, 'kHz'), 'reported_clock_detail': det}

def _vlt(data: bytes, off2: int) -> dict:
    dom, fla, rep2 = st2.unpack_from('<3I', data, off2)
    return {'byte_offset': off2, 'domain': dom, 'editable': bool(fla & 1), 'reserved_flag_bits': fla & 4294967294, 'reported_base_voltage_uv': rep2, 'voltage_delta': _dlt(data, off2 + 12, 'uV'), 'meaning': 'base voltage field is separate from the explicitly requested voltage delta'}

def prs(data: bytes, con: str='unknown') -> dict:
    if con not in ('unknown', 'snapshot', 'request'):
        raise PpErr('context must be unknown, snapshot or request')
    if len(data) < hea_byt:
        raise PpErr('truncated PStates header')
    ver5, fla, nst, ncl, nvo = st2.unpack_from('<5I', data)
    if ver5 not in ver2:
        raise PpErr(f'unsupported complete structure version {ver5:#x}')
    lab, req3 = ver2[ver5]
    if len(data) < req3:
        raise PpErr(f'truncated {lab} packet: need {req3}, got {len(data)}')
    if nst > max_sts or ncl > max_clks or nvo > max_vlts:
        raise PpErr('PStates count exceeds fixed ABI capacity')
    sts = []
    for ind2 in range(nst):
        sta2 = hea_byt + ind2 * st_byt
        st_id, st_fla = st2.unpack_from('<2I', data, sta2)
        sts.append({'byte_offset': sta2, 'state_id': st_id, 'editable': bool(st_fla & 1), 'reserved_flag_bits': st_fla & 4294967294, 'clocks': [_clk(data, sta2 + 8 + i * clk_byt) for i in range(ncl)], 'base_voltage_entries': [_vlt(data, sta2 + 8 + max_clks * clk_byt + i * vlt_byt) for i in range(nvo)]})
    rel = []
    if req3 == v_2_byt:
        cou = _u32(data, v_1_byt)
        if cou > max_vlts:
            raise PpErr('Relative-voltage extension count exceeds ABI capacity')
        rel = [_vlt(data, v_1_byt + 4 + i * vlt_byt) for i in range(cou)]
    return {'format': 'NV_GPU_PERF_PSTATES20_INFO', 'context': con, 'version': hex(ver5), 'abi_revision': lab, 'declared_structure_bytes': req3, 'input_bytes': len(data), 'trailing_bytes': len(data) - req3, 'editable': bool(fla & 1), 'reserved_flag_bits': fla & 4294967294, 'num_states': nst, 'num_clocks_per_state': ncl, 'num_base_voltages_per_state': nvo, 'states': sts, 'relative_voltage_entries': rel, 'limits': ['Offline ABI decoding is not validation of safe operating settings.', 'Unpopulated entries are omitted, not interpreted as requested zero values.', 'Getter snapshot fields must not be blindly copied into a setter request.', 'Reported voltage metadata and explicitly requested voltage deltas are different fields.']}

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('file', type=Path)
    ap.add_argument('--context', choices=['unknown', 'snapshot', 'request'], default='unknown')
    args = ap.parse_args()
    if args.file.stat().st_size > 65536:
        ap.error('Packet exceeds 64 KiB analysis limit')
    try:
        res4 = prs(args.file.read_bytes(), args.context)
    except (PpErr, OSError) as exc:
        ap.exit(1, f'Error: {exc}\n')
    print(json.dumps(res4, indent=2, ensure_ascii=True))
if __name__ == '__main__':
    main()
