# _pe_
from pathlib import Path
import hashlib as has2, json, re, subprocess as sub2
import pefile as pef
from to import rec2
from tr import prs_json_str
root2 = Path(__file__).resolve().parents[1]
OUT = root2 / 'analysis/phase7'

def cho(mod3):
    sel = []
    int_met = {'GpuGetPstates20', 'GpuSetPstates20', 'GpuGetPerfClocks', 'GpuSetPerfClocks', 'GpuClientPowerPoliciesGetInfo', 'GpuClientPowerPoliciesGetStatus', 'GpuClientPowerPoliciesSetStatus'}
    bac_met = {'SetClockBoost', 'GetCoreClockBoost', 'GetMemoryClockBoost', 'VDDC_SetVoltage', 'VDDC_SetVoltageBoost', 'VDDC_GetVoltage', 'VDDC_GetVoltageBoost', 'VDDC_GetVoltageBoostMin', 'VDDC_GetVoltageBoostMax', 'IsCoreClockBoostControlSupported', 'IsMemoryClockBoostControlSupported', 'SetVoltageFrequencyCurve', 'GetVoltageFrequencyCurve'}
    for item in mod3['exports']:
        mat = re.match('^\\?([^@]+)@([^@]+)@@', item['name'] or '')
        if not mat:
            continue
        met2, cls = mat.groups()
        yes = cls == 'CNVAPIWrapper' and (met2.startswith(('PS20_', 'VFCurve_', 'ClientVoltageRail_')) or met2 in {'SetPerfClocks', 'GetPerfClocks', 'SetPowerControl', 'RestoreDevice'})
        yes |= cls == 'CNVAPIInterface' and met2 in int_met
        yes |= cls == 'CHALImplementationNVAPI' and met2 in bac_met
        if yes:
            sel.append({'name': cls + '.' + met2, 'rva': int(item['rva'], 16), 'decorated': item['name']})
    return sorted(sel, key=lambda x: x['rva'])

def sel3(fn):
    mat2 = []
    ops = sorted(fn.get('ops', []), key=lambda op: op['offset'])
    for i, op in enumerate(ops):
        mat = re.fullmatch('push (0x[0-9a-fA-F]+)', op.get('disasm', ''))
        if not mat:
            continue
        val = int(mat[1], 16) & 4294967295
        if i + 1 < len(ops) and ops[i + 1].get('disasm') == 'call eax':
            mat2.append({'site_va': hex(op['offset']), 'literal': hex(val), 'following_call': ops[i + 1]['disasm'], 'classification': 'candidate dynamic query selector; not a function address'})
    return mat2

def main():
    inv2 = json.loads((root2 / 'analysis/inventory/pe_inventory.json').read_text(encoding='utf-8-sig'))
    mod3 = next((x for x in inv2['modules'] if x['path'] == 'RTHAL.dll'))
    path = root2 / 'afterb/MSI Afterburner/RTHAL.dll'
    OUT.mkdir(parents=True, exist_ok=True)
    r2 = root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe'
    sel = cho(mod3)
    fns2 = rec2(mod3, path, sel, r2, OUT)
    kno = {int(item['rva'], 16) for item in fns2}
    thu2 = []
    for f in fns2:
        if f['name'].startswith('CNVAPIInterface.') or f['name'].startswith(('CNVAPIWrapper.VFCurve_', 'CNVAPIWrapper.ClientVoltageRail_')):
            for edge in f['calls_and_tail_jumps']:
                if edge['resolution'] == 'direct_unlabelled' and edge['target_va']:
                    rva = int(edge['target_va'], 16) - int(mod3['image_base'], 16)
                    if 4096 <= rva < 131072 and rva not in kno:
                        thu2.append({'name': 'DynamicThunk', 'rva': rva})
                        kno.add(rva)
    fns2 += rec2(mod3, path, sorted(thu2, key=lambda t: t['rva']), r2, OUT)
    bin2 = []
    for f in fns2:
        if f['name'] == 'DynamicThunk':
            raw = json.loads((OUT / (f['artifact_prefix'] + '.json')).read_text())
            bin2.append({'thunk_rva': f['rva'], 'artifact_prefix': f['artifact_prefix'], 'query_literals': sel3(raw), 'indirect_calls': [edge for edge in f['calls_and_tail_jumps'] if edge['resolution'] == 'unresolved_indirect']})
    rpt = {'mode': 'static only', 'target_code_executed': False, 'hardware_writes': False, 'module': {k: mod3[k] for k in ['path', 'sha256', 'image_base']}, 'functions': fns2, 'dynamic_bindings': bin2, 'limits': ['Indirect calls are not automatically resolved to hardware operations.', 'Static evidence does not imply an executing branch or safe operating limits.']}
    (OUT / 'core-callgraph.json').write_text(json.dumps(rpt, indent=2) + '\n', encoding='utf-8')
    ven = Path(__import__('os').environ['WINDIR']) / 'System32/nvapi64.dll'
    with pef.PE(str(ven)) as pe:
        exp = [{'name': e.name.decode('ascii', 'replace') if e.name else None, 'rva': hex(e.address)} for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        que = next((e for e in exp if e['name'] == 'nvapi_QueryInterface'))
        va = pe.OPTIONAL_HEADER.ImageBase + int(que['rva'], 16)
        meta = {'path': str(ven), 'sha256': has2.sha256(ven.read_bytes()).hexdigest(), 'machine': hex(pe.FILE_HEADER.Machine), 'image_base': hex(pe.OPTIONAL_HEADER.ImageBase), 'query_export': que, 'exports': exp, 'imports': [{'dll': e.dll.decode('ascii', 'replace'), 'names': [i.name.decode('ascii', 'replace') if i.name else '#' + str(i.ordinal) for i in e.imports]} for e in pe.DIRECTORY_ENTRY_IMPORT]}
    run = sub2.run([str(r2), '-2', '-q', '-e', 'scr.color=false', '-c', f'af @ {va:#x};pdfj @ {va:#x}', str(ven)], capture_output=True, check=True, timeout=90)
    (OUT / 'system-nvapi-query.jsonstream').write_bytes(run.stdout)
    (OUT / 'system-nvapi-static.json').write_text(json.dumps(meta, indent=2) + '\n')
    print('Core functions:', len(fns2), 'dynamic thunks:', len(bin2))
    for item in bin2:
        print(item['thunk_rva'], [x['literal'] for x in item['query_literals']])
    print('System NVAPI query export:', que, 'file hash', meta['sha256'])
if __name__ == '__main__':
    main()
