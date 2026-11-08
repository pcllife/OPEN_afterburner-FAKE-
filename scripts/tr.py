# _pe_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
from pathlib import Path
import re
import subprocess as sub2
import struct as st2
import pefile as pef
root2 = Path(__file__).resolve().parents[1]
sym2 = re.compile('^\\?([^@]+)@([^@]+)@@')
sig2 = {'CHAL': {'SetClocks', 'SetClockBoost', 'SetPowerLimit', 'GetGpuUsage', 'GetCpuUsage', 'Init'}, 'CHALImplementationNVAPI': {'SetClocks', 'SetClockBoost', 'SetPowerLimit', 'GetGpuUsage'}, 'CHALImplementationATIADL': {'SetClocks', 'SetClockBoost', 'SetPowerLimit', 'GetGpuUsage'}, 'CHALImplementationIGCL': {'SetClocks', 'SetClockBoost', 'SetPowerLimit', 'GetGpuUsage'}, 'CHALImplementation': {'GetGpuUsage', 'GetHwGpuUsage', 'GetCpuUsage'}, 'CNVAPIWrapper': {'SetPerfClocks', 'SetPstate', 'SetPowerControl', 'GetUtilizations', 'GetUnifiedActivityMonitoring', 'SetTimestamp', 'Init', 'PS20_SetCoreClockBoost', 'PS20_SetMemoryClockBoost', 'PS20_SetClockBoost', 'VFCurve_SetClockBoost', 'VFCurve_GetCoreClockMultiplier', 'VFCurve_IsSupported'}, 'CNVAPIInterface': {'Init', 'GpuGetDynamicPstatesInfoEx', 'GpuGetUsages', 'GpuGetUtilization', 'GpuSetPstates20', 'GpuSetPerfClocks', 'GpuSetPstatesInfo', 'GpuClientPowerPoliciesSetStatus'}, 'CATIADLWrapper': {'SetPerfClocks', 'GetCurrentActivity', 'SetPowerControl'}}

def prs_json_str(text: str) -> list[dict]:
    dec2, res4 = (json.JSONDecoder(), [])
    rem = text.strip()
    while rem:
        item, end = dec2.raw_decode(rem)
        res4.append(item)
        rem = rem[end:].lstrip()
    return res4

def dec_ctl_code(val: int) -> dict:
    return {'device_type': hex(val >> 16), 'access': val >> 14 & 3, 'function': hex(val >> 2 & 4095), 'method': val & 3}

def tar(mod3: dict) -> list[dict]:
    res4 = []
    for exp in mod3['exports']:
        mat = sym2.match(exp['name'] or '')
        if not mat:
            continue
        met2, cls = mat.groups()
        if mod3['path'] == 'RTCore.dll' and cls == 'CRTCoreDriver' or met2 in sig2.get(cls, set()):
            res4.append({'name': f'{cls}.{met2}', 'decorated': exp['name'], 'rva': int(exp['rva'], 16)})
    if mod3['path'] == 'RTHAL.dll':
        res4 += [{'name': name, 'decorated': None, 'rva': rva} for name, rva in [('NvapiDynamicPstatesThunk', 40880), ('VFCurveQueryThunk', 46960), ('VFCurveStatusThunk', 47376), ('VFCurveSubmitThunk', 47584)]]
    if mod3['path'] == 'RTCore64.sys':
        res4 = [{'name': name, 'decorated': None, 'rva': rva} for name, rva in [('EntryWrapper', 32868), ('Initialize', 6960), ('Dispatch', 5176), ('Unload', 4104)]]
    return res4

def sym_for(mod3: dict) -> tuple[dict[int, str], dict[int, str]]:
    base = int(mod3['image_base'], 16)
    exp4 = {base + int(exp['rva'], 16): exp['name'] for exp in mod3['exports'] if exp['name']}
    imp2 = {int(imp['iat_va'], 16): f"{imp['dll']}!{imp['name'] or imp['ordinal']}" for imp in mod3['imports']}
    return (exp4, imp2)

def call_edg(fn: dict, mod3: dict) -> list[dict]:
    exp3, imp2 = sym_for(mod3)
    base = int(mod3['image_base'], 16)
    res4 = []
    for op in fn.get('ops', []):
        kind = op.get('type', '')
        if 'call' not in kind and kind not in ('jmp', 'ujmp'):
            continue
        dest = op.get('jump')
        ptr2 = op.get('ptr')
        if ptr2 in imp2:
            res2, lab = ('iat', imp2[ptr2])
        elif dest in exp3:
            res2, lab = ('export', exp3[dest])
        elif dest is not None:
            res2, lab = ('direct_unlabelled', hex(dest))
        else:
            res2, lab = ('unresolved_indirect', op.get('disasm', ''))
        res4.append({'site_rva': hex(op['offset'] - base), 'instruction': op.get('disasm', ''), 'kind': kind, 'resolution': res2, 'target': lab, 'target_va': hex(dest) if dest is not None else None})
    return res4

def ioc_lit(fn: dict, edg: list[dict], base: int) -> list[dict]:
    cal = {int(edge['site_rva'], 16) + base for edge in edg if edge['resolution'] == 'iat' and edge['target'].endswith('!DeviceIoControl')}
    res4, pus = ([], [])
    for op in sorted(fn.get('ops', []), key=lambda item: item['offset']):
        text = op.get('disasm', '')
        if op['offset'] in cal:
            if len(pus) >= 8:
                args = list(reversed(pus[-8:]))
                try:
                    code = int(args[1], 0)
                except ValueError:
                    code = None
                if code is not None and 2147483648 <= code <= 4294967295:

                    def lit(ind2):
                        try:
                            return int(args[ind2], 0)
                        except ValueError:
                            return None
                    res4.append({'call_rva': hex(op['offset'] - base), 'code': hex(code), 'ctl_code': dec_ctl_code(code), 'input_length_literal': lit(3), 'output_length_literal': lit(5), 'argument_operands': args, 'evidence': 'literal pushes on final straight-line call segment'})
            pus = []
        elif text.startswith('push '):
            pus.append(text[5:].strip())
        elif 'call' in op.get('type', '') or op.get('type') in ('cjmp', 'jmp', 'ret', 'pop'):
            pus = []
    return res4

def vta_evi(path: Path, mod3: dict) -> list[dict]:
    exp3, _ = sym_for(mod3)
    base = int(mod3['image_base'], 16)
    res4 = []
    tab = ('??_7CHALImplementationNVAPI@@6B@', '??_7CHALImplementationATIADL@@6B@', '??_7CHALImplementationIGCL@@6B@', '??_7CHALImplementationUnified@@6B@')
    with pef.PE(str(path)) as pe:
        for exp in mod3['exports']:
            if exp['name'] not in tab:
                continue
            rva = int(exp['rva'], 16)
            for slot in (84, 88, 92, 396):
                tgt = st2.unpack('<I', pe.get_data(rva + slot, 4))[0]
                res4.append({'vtable': exp['name'], 'vtable_rva': hex(rva), 'slot_offset': hex(slot), 'target_rva': hex(tgt - base), 'target_export': exp3.get(tgt), 'evidence': 'x86 PE vtable dword at declared slot; not live dispatch'})
    return res4

def dsp_cas(fn: dict, base: int) -> list[dict]:
    ops = sorted(fn.get('ops', []), key=lambda item: item['offset'])
    res4, r_8_code = ([], None)
    for ind2, op in enumerate(ops[:-1]):
        ins2 = op.get('disasm', '')
        if ins2.startswith('mov r8d, 0x800020'):
            r_8_code = int(ins2.split(', ')[1], 16)
        if not ins2.startswith('cmp eax, '):
            continue
        rhs = ins2.split(', ', 1)[1]
        try:
            code = r_8_code if rhs == 'r8d' else int(rhs, 0)
        except ValueError:
            continue
        if code is None or not 2147491840 <= code <= 2147492095:
            continue
        bra = ops[ind2 + 1]
        text = bra.get('disasm', '')
        if text.startswith(('je ', 'jz ')):
            tgt = bra.get('jump')
        elif text.startswith(('jne ', 'jnz ')):
            tgt = bra.get('fail', bra['offset'] + bra.get('size', 0))
        else:
            continue
        if tgt is not None:
            res4.append({'code': hex(code), 'compare_rva': hex(op['offset'] - base), 'handler_rva': hex(tgt - base), 'evidence': 'top-level EAX control-code equality branch'})
    return res4

def asm_text(fn: dict, mod3: dict, sel: dict, edg: list[dict]) -> str:
    base = int(mod3['image_base'], 16)
    by_site = {int(edge['site_rva'], 16) + base: edge for edge in edg}
    lin = [f"; {mod3['path']} :: {sel['name']}", f"; SHA256 {mod3['sha256']}", f"; preferred ImageBase={base:#x}, entry RVA={sel['rva']:#x}", '; Static function recovery; indirect targets are not assumed resolved.']
    for op in sorted(fn.get('ops', []), key=lambda item: item['offset']):
        edge = by_site.get(op['offset'])
        note = f" ; {edge['resolution']}: {edge['target']}" if edge else ''
        lin.append(f"{op['offset']:016x} {op.get('bytes', ''):24s} {op.get('disasm', '')}{note}")
    return '\n'.join(lin) + '\n'

def main() -> None:
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, default=root2 / 'afterb' / 'MSI Afterburner')
    ap.add_argument('--out', type=Path, default=root2 / 'analysis' / 'phase2')
    ap.add_argument('--r2', type=Path, default=root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe')
    ap.add_argument('--inventory', type=Path, default=root2 / 'analysis/inventory/pe_inventory.json')
    args = ap.parse_args()
    base, out, r2 = (args.base.resolve(), args.out.resolve(), args.r2.resolve())
    if not base.is_dir() or not r2.is_file():
        ap.error('Sample directory or radare2 executable is missing')
    if out == base or base in out.parents:
        ap.error('Output must be outside the sample directory')
    inv2 = json.loads(args.inventory.read_text(encoding='utf-8-sig'))
    mods = [mod3 for mod3 in inv2['modules'] if mod3['path'] in ('RTHAL.dll', 'RTCore.dll', 'RTCore64.sys')]
    out.mkdir(parents=True, exist_ok=True)
    res4 = {'method': 'static radare2 recovery, export/IAT-resolved direct edges', 'modules': [], 'functions': [], 'ioctl_wrappers': [], 'vtable_slots': [], 'driver_cases': []}
    for mod3 in mods:
        path = base / mod3['path']
        act_hash = has2.sha256(path.read_bytes()).hexdigest()
        if act_hash != mod3['sha256']:
            raise RuntimeError(f"Sample changed since inventory: {mod3['path']}")
        sel = tar(mod3)
        if mod3['path'] == 'RTHAL.dll':
            res4['vtable_slots'].extend(vta_evi(path, mod3))
        ima_base = int(mod3['image_base'], 16)
        com2 = 'aa;' + ';'.join((f"af @ {ima_base + item['rva']:#x};pdfj @ {ima_base + item['rva']:#x}" for item in sel))
        proc = sub2.run([str(r2), '-2', '-q', '-e', 'scr.color=false', '-c', com2, str(path)], capture_output=True, timeout=120, check=True)
        rec3 = prs_json_str(proc.stdout.decode('utf-8', errors='replace'))
        if len(rec3) != len(sel):
            raise RuntimeError(f'Expected {len(sel)} functions, got {len(rec3)} for {path}')
        res4['modules'].append({'path': mod3['path'], 'sha256': act_hash, 'image_base': mod3['image_base'], 'selected_functions': len(sel)})
        for item, fn in zip(sel, rec3):
            slug = f"{Path(mod3['path']).stem}-{item['name']}-{item['rva']:x}"
            (out / (slug + '.json')).write_text(json.dumps(fn, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
            edg = call_edg(fn, mod3)
            (out / (slug + '.asm')).write_text(asm_text(fn, mod3, item, edg), encoding='utf-8')
            sum3 = {'module': mod3['path'], 'name': item['name'], 'rva': hex(item['rva']), 'decorated': item['decorated'], 'bytes_reported': fn.get('size'), 'ops_recovered': len(fn.get('ops', [])), 'calls_and_tail_jumps': edg, 'artifact_prefix': slug}
            res4['functions'].append(sum3)
            if mod3['path'] == 'RTCore64.sys' and item['name'] == 'Dispatch':
                res4['driver_cases'].extend(dsp_cas(fn, ima_base))
            if mod3['path'] == 'RTCore.dll':
                for req2 in ioc_lit(fn, edg, ima_base):
                    res4['ioctl_wrappers'].append({'wrapper': item['name'], 'wrapper_rva': hex(item['rva']), **req2})
        print(f"{mod3['path']}: {len(sel)} focused functions")
    cas = {case['code']: case for case in res4['driver_cases']}
    for wra in res4['ioctl_wrappers']:
        wra['kernel_handler_rva'] = cas.get(wra['code'], {}).get('handler_rva')
    with (out / 'ioctl-wrapper-catalog.csv').open('w', encoding='utf-8', newline='') as str2:
        import csv
        wri = csv.DictWriter(str2, fieldnames=['wrapper', 'wrapper_rva', 'code', 'input_length_literal', 'output_length_literal', 'kernel_handler_rva'])
        wri.writeheader()
        wri.writerows(({key: item.get(key) for key in wri.fieldnames} for item in res4['ioctl_wrappers']))
    (out / 'callgraph.json').write_text(json.dumps(res4, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"{len(res4['functions'])} functions; {len(res4['ioctl_wrappers'])} literal IOCTL wrapper matches")
    print(f"Report: {out / 'callgraph.json'}")
if __name__ == '__main__':
    main()
