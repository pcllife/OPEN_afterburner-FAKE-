# _pe_
from pathlib import Path
import argparse as arg
import hashlib as has2
import json
import re
import subprocess as sub2
from tr import prs_json_str, call_edg, asm_text
root2 = Path(__file__).resolve().parents[1]
met = {'CHAL': {'SetClocks', 'SetClockBoost', 'SetDefaultClocks', 'GetDefaultCoreClockBoost', 'GetDefaultMemoryClockBoost', 'SetPowerLimit', 'LockClockControl', 'IsClockControlLocked'}, 'CHALImplementationNVAPI': {'SetClocks', 'SetClockBoost', 'SetDefaultClocks', 'GetCoreClockBoostMin', 'GetCoreClockBoostMax', 'GetMemoryClockBoostMin', 'GetMemoryClockBoostMax', 'GetDefaultCoreClockBoost', 'GetDefaultMemoryClockBoost', 'GetDefaultCoreClock', 'GetDefaultMemoryClock', 'GetDefaultPowerLimit', 'GetPowerLimitMin', 'GetPowerLimitMax', 'SetPowerLimit'}, 'CNVAPIWrapper': {'PS20_GetClockBoost', 'PS20_GetCoreClockBoost', 'PS20_GetMemoryClockBoost', 'PS20_SetClockBoost', 'PS20_SetCoreClockBoost', 'PS20_SetMemoryClockBoost', 'PS20_IsSupported', 'VFCurve_GetClockBoostRanges', 'VFCurve_GetCoreClockMultiplier', 'VFCurve_SetClockBoost', 'VFCurve_SetCurve', 'VFCurve_IsSupported', 'SetPerfClocks', 'SetPowerControl', 'GetPowerControlRange', 'RestoreDevice', 'GetPerfClocks', 'GetClocks'}, 'CNVAPIInterface': {'GpuSetPstates20', 'GpuGetPstates20', 'GpuSetPerfClocks', 'GpuClientPowerPoliciesGetInfo', 'GpuClientPowerPoliciesSetStatus'}}
main_rvas = {364578: 'ApplyStagedSettings', 348553: 'ClockRangeAndQuantization', 348393: 'ValueQuantization', 349500: 'LoadStagedSettings'}

def rec2(mod3, path, tar, r2, out):
    dig = has2.sha256(path.read_bytes()).hexdigest()
    if dig != mod3['sha256']:
        raise RuntimeError('Sample no longer matches inventory: ' + mod3['path'])
    base = int(mod3['image_base'], 16)
    com = 'aa;' + ';'.join((f"af-*;af @ {base + t['rva']:#x};pdfj @ {base + t['rva']:#x}" for t in tar))
    run = sub2.run([str(r2), '-2', '-q', '-e', 'scr.color=false', '-c', com, str(path)], capture_output=True, check=True, timeout=120)
    fns2 = prs_json_str(run.stdout.decode('utf-8', 'replace'))
    if len(fns2) != len(tar):
        raise RuntimeError('Function extraction count mismatch')
    rs = []
    for tgt, fn in zip(tar, fns2):
        ops = fn.get('ops', [])
        if not ops or fn.get('addr') != base + tgt['rva']:
            raise RuntimeError('Missing or shifted function: ' + tgt['name'])
        edg = call_edg(fn, mod3)
        stem = Path(mod3['path']).stem + '-' + tgt['name'] + '-' + format(tgt['rva'], 'x')
        (out / (stem + '.asm')).write_text(asm_text(fn, mod3, tgt, edg), encoding='utf-8')
        (out / (stem + '.json')).write_text(json.dumps(fn, indent=2) + '\n', encoding='utf-8')
        rs.append({'module': mod3['path'], 'name': tgt['name'], 'rva': hex(tgt['rva']), 'decorated': tgt.get('decorated'), 'artifact_prefix': stem, 'ops': len(ops), 'calls_and_tail_jumps': edg})
    print(mod3['path'], len(rs), 'functions, SHA256 verified')
    return rs

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, default=root2 / 'analysis/phase4')
    args = ap.parse_args()
    out = args.out.resolve()
    base = (root2 / 'afterb/MSI Afterburner').resolve()
    if out == base or base in out.parents:
        ap.error('Reports must be outside sample directory')
    inv2 = json.loads((root2 / 'analysis/inventory/pe_inventory.json').read_text(encoding='utf-8-sig'))
    out.mkdir(parents=True, exist_ok=True)
    rpt = {'mode': 'offline static only', 'hardware_calls_executed': False, 'modules': [], 'functions': []}
    for mod3 in inv2['modules']:
        if mod3['path'] not in ('RTHAL.dll', 'MSIAfterburner.exe'):
            continue
        tar = []
        if mod3['path'] == 'RTHAL.dll':
            for ent in mod3['exports']:
                mat = re.match('^\\?([^@]+)@([^@]+)@@', ent['name'] or '')
                if mat and mat[1] in met.get(mat[2], set()):
                    tar.append({'name': mat[2] + '.' + mat[1], 'rva': int(ent['rva'], 16), 'decorated': ent['name']})
        else:
            tar = [{'name': name, 'rva': rva} for rva, name in main_rvas.items()]
        tar.sort(key=lambda x: x['rva'])
        rpt['modules'].append({key: mod3[key] for key in ['path', 'sha256', 'image_base']})
        rpt['functions'] += rec2(mod3, base / mod3['path'], tar, root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe', out)
    (out / 'overclock-callgraph.json').write_text(json.dumps(rpt, indent=2) + '\n', encoding='utf-8')
    print('Total', len(rpt['functions']), 'functions; report', out / 'overclock-callgraph.json')
if __name__ == '__main__':
    main()
