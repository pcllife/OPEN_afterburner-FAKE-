# _abi_
import argparse as arg
import ctypes as C
import datetime as dat
import hashlib as has2
import json
import os
from pathlib import Path
from ob import Nv, Ps, OcErr
from pp import PpErr, prs
from pc import PcErr, plan_clk_cha
root2 = Path(__file__).resolve().parents[1]
rd_only_ids = frozenset({22079528, 3526090110, 3853292063, 3471740575, 769635950, 467712229, 1878528531, 3814984278})

class Cap(Nv):

    def __init__(self):
        self.resolved_selectors = []
        try:
            super().__init__(ok_set=False)
        except Exception:
            self.close()
            raise
        if self.setter is not None:
            self.close()
            raise OcErr('Capture must never have a setter')

    def resolve(self, sel2, res3, arg2):
        if sel2 not in rd_only_ids:
            raise OcErr('Selector outside the getter-only capture allowlist')
        self.resolved_selectors.append(hex(sel2))
        return super().resolve(sel2, res3, arg2)

def col2():
    if os.name != 'nt':
        raise OcErr('Windows-only getter capture')
    is64 = C.sizeof(C.c_void_p) == 8
    src2 = Path(os.environ['WINDIR']) / ('System32/nvapi64.dll' if is64 else 'SysWOW64/nvapi.dll')
    man = root2 / 'analysis/phase7' / ('vendor-dispatch.json' if is64 else 'vendor32-dispatch.json')
    exp2 = json.loads(man.read_text(encoding='utf-8'))['module']['sha256']
    if has2.sha256(src2.read_bytes()).hexdigest() != exp2:
        raise OcErr('NVAPI file differs from the pinned analysis sample')
    sta3 = dat.datetime.now(dat.timezone.utc).isoformat()
    with Cap() as api:
        pkt = Ps()
        pkt.version = 72852
        api.check(api.get(api.gpu, C.byref(pkt)), 'read-only GetPstates20 V1')
        raw = bytes(pkt)
        idn = dict(api.identity)
        tmp2 = api.temperature()
        sel3 = list(api.resolved_selectors)
    dec = prs(raw, 'snapshot')
    pla = {}
    for dom, name in [(0, 'graphics'), (4, 'memory')]:
        try:
            st = next((s for s in dec['states'] if s['state_id'] == 0))
            clk = next((c for c in st['clocks'] if c['domain'] == dom))
            pla[name] = plan_clk_cha(raw, dom, clk['frequency_delta']['value'])
            pla[name]['purpose'] = 'offline no-change plan; never submitted'
        except (PcErr, StopIteration) as exc:
            pla[name] = {'mode': 'offline no-change preflight', 'passed': False, 'reason': str(exc) or 'P0 or requested clock domain absent'}
    md = {'mode': 'live read-only getter capture', 'hardware_writes': False, 'captured_at_utc': sta3, 'identity': idn, 'temperature_c': tmp2, 'process_bits': C.sizeof(C.c_void_p) * 8, 'nvapi_file': str(src2), 'nvapi_sha256': exp2, 'resolved_selectors': sel3, 'setter_resolved': False, 'raw_packet_sha256': has2.sha256(raw).hexdigest(), 'scope': 'Separate getter process; no Afterburner injection, setter invocation or live branch tracing.'}
    return (raw, dec, pla, md)

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--out-dir', required=True, type=Path, help='New directory only; existing paths are rejected')
    args = ap.parse_args()
    if args.out_dir.exists():
        ap.error('Output directory already exists; previous captures are not overwritten')
    try:
        raw, dec, pla, md = col2()
        args.out_dir.mkdir(parents=True, exist_ok=False)
        (args.out_dir / 'pstates-v1.bin').write_bytes(raw)
        for name, val in {'capture.json': md, 'decoded.json': dec, **{k + '-nochange-plan.json': v for k, v in pla.items()}}.items():
            (args.out_dir / name).write_text(json.dumps(val, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'directory': str(args.out_dir), 'metadata': md, 'nochange_preflight': {k: v.get('offline_contract_checks_passed', False) for k, v in pla.items()}}, indent=2))
    except (OSError, OcErr, PcErr, PpErr) as exc:
        ap.exit(2, f'Error: {exc}\n')
if __name__ == '__main__':
    main()
