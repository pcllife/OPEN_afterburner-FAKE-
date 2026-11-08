# _pe_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
import os
from pathlib import Path
import struct as st2
import subprocess as sub2
import pefile as pef
from tr import prs_json_str, call_edg, asm_text
root2 = Path(__file__).resolve().parents[1]
hel = {1778480: 'PStatesSubmitInternal', 3011120: 'PStatesPrecheckA', 3006896: 'PStatesPrecheckB', 3015040: 'PStatesPrecheckC', 3008208: 'PStatesPrecheckD', 1426768: 'QueryAlternativeDispatch', 1782784: 'NormalizedPStatesSubmit', 1781120: 'PStatesCapabilityRead', 2272720: 'PStatesInternalRead', 788080: 'AfterClockSubmit', 4180480: 'InternalControlTransport', 4110464: 'TransportHelperCandidate', 601776: 'TranslateControlStatus', 4181024: 'ControlForwarder', 4182000: 'ControlForwarderDispatch'}
nam = {1878528531: 'NvAPI_GPU_GetPstates20', 256749163: 'Recovered_GpuSetPstates20', 1625215725: 'NvAPI_GPU_GetDynamicPstatesInfoEx'}

def prs_tbl(pe, sta_rva, max_ents=8192, ptr_size=8):
    if ptr_size not in (4, 8):
        raise ValueError('Pointer size must be 4 or 8')
    str3 = 8 if ptr_size == 4 else 16
    ima_base = pe.OPTIONAL_HEADER.ImageBase
    sec4 = pe.get_section_by_rva(sta_rva)
    if sec4 is None:
        raise ValueError('Dispatch table is not inside a PE section')
    tbl_end = sec4.VirtualAddress + sec4.SizeOfRawData
    ents2 = []
    for ind2 in range(max_ents):
        rva = sta_rva + ind2 * str3
        if rva + str3 > tbl_end:
            raise ValueError('No table terminator before raw section boundary')
        data = pe.get_data(rva, str3)
        if len(data) != str3:
            raise ValueError('Truncated dispatch table')
        if ptr_size == 8:
            ptr2, sel2, res = st2.unpack('<QII', data)
        else:
            ptr2, sel2 = st2.unpack('<II', data)
            res = 0
        if ptr2 == 0:
            return ents2
        tgt = ptr2 - ima_base
        code = pe.get_section_by_rva(tgt)
        if not code or not code.Characteristics & 536870912:
            raise ValueError('Dispatch target is not executable: ' + hex(ptr2))
        ents2.append({'table_entry_rva': hex(rva), 'selector': hex(sel2), 'target_rva': hex(tgt), 'reserved': res})
    raise ValueError('Unterminated dispatch table exceeds bound')

def ext3(path, mod3, tar, r2, out, pre='SystemNVAPI'):
    if not tar:
        return []
    base = int(mod3['image_base'], 16)
    cmd = ';'.join((f"af-*;af @ {base + t['rva']:#x};pdfj @ {base + t['rva']:#x}" for t in tar))
    run = sub2.run([str(r2), '-2', '-q', '-e', 'scr.color=false', '-c', cmd, str(path)], capture_output=True, check=True, timeout=120)
    fns2 = prs_json_str(run.stdout.decode('utf-8', 'replace'))
    if len(fns2) != len(tar):
        raise ValueError('Wrong number of recovered functions')
    res4 = []
    for tgt, fn in zip(tar, fns2):
        if fn.get('addr') != base + tgt['rva'] or not fn.get('ops'):
            raise ValueError('Empty or shifted function ' + tgt['name'])
        stem = pre + '-' + tgt['name'] + '-' + format(tgt['rva'], 'x')
        edg = call_edg(fn, mod3)
        (out / (stem + '.json')).write_text(json.dumps(fn, indent=2) + '\n', encoding='utf-8')
        (out / (stem + '.asm')).write_text(asm_text(fn, mod3, tgt, edg), encoding='utf-8')
        res4.append({'name': tgt['name'], 'rva': hex(tgt['rva']), 'artifact_prefix': stem, 'ops': len(fn['ops']), 'calls_and_tail_jumps': edg})
    return res4

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, default=root2 / 'analysis/phase7')
    args = ap.parse_args()
    out = args.out.resolve()
    path = Path(os.environ['WINDIR']) / 'System32/nvapi64.dll'
    if out == path.parent or path.parent in out.parents:
        ap.error('Output cannot be a system directory')
    out.mkdir(parents=True, exist_ok=True)
    meta = json.loads((root2 / 'analysis/phase7/system-nvapi-static.json').read_text())
    if has2.sha256(path.read_bytes()).hexdigest() != meta['sha256']:
        raise ValueError('Installed NVAPI changed; regenerate and re-audit target RVAs first')
    core = json.loads((root2 / 'analysis/phase7/core-callgraph.json').read_text())
    sel3 = {int(x['literal'], 16) for b in core['dynamic_bindings'] for x in b['query_literals']}
    r2 = root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe'
    with pef.PE(str(path)) as pe:
        base = pe.OPTIONAL_HEADER.ImageBase
        tbl = next((s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.data')).VirtualAddress
        que_byt = pe.get_data(1426641, 7)
        if que_byt[:3] != b'L\x8d\x05':
            raise ValueError('Query table-anchor instruction changed')
        res2 = 1426641 + 7 + st2.unpack('<i', que_byt[3:])[0]
        if res2 != tbl:
            raise ValueError('Query branch does not reference expected table')
        ents2 = prs_tbl(pe, tbl)
        sel = [dict(e, name=nam.get(int(e['selector'], 16), 'Selector_' + format(int(e['selector'], 16), '08x'))) for e in ents2 if int(e['selector'], 16) in sel3 or int(e['selector'], 16) in nam]
        mod3 = {'path': 'system-nvapi64.dll', 'sha256': meta['sha256'], 'image_base': hex(base), 'exports': [{'name': e['name'], 'rva': e['target_rva']} for e in sel], 'imports': [{'dll': m.dll.decode('ascii', 'replace'), 'name': i.name.decode('ascii', 'replace') if i.name else None, 'ordinal': i.ordinal, 'iat_va': hex(i.address)} for m in pe.DIRECTORY_ENTRY_IMPORT for i in m.imports]}
    fns2 = ext3(path, mod3, [{'name': e['name'], 'rva': int(e['target_rva'], 16)} for e in sel], r2, out)
    for ent, fn in zip(sel, fns2):
        ent.update(fn)
    unr = [hex(s) for s in sorted(sel3) if not any((int(e['selector'], 16) == s for e in sel))]
    dsp = {'mode': 'static only; no selectors called', 'module': mod3, 'table_rva': hex(tbl), 'table_stride': 16, 'table_entries': len(ents2), 'query_anchor_rva': '0x15c4d1', 'selected_bindings': sel, 'unresolved_selectors': unr, 'limits': ['Pinned NVIDIA driver 560.94 only; not a cross-version layout guarantee.', 'QueryInterface has an alternative conditional path; recovered table is the legacy branch.']}
    (out / 'vendor-dispatch.json').write_text(json.dumps(dsp, indent=2) + '\n', encoding='utf-8')
    hel2 = ext3(path, mod3, [{'name': name, 'rva': rva} for rva, name in hel.items()], r2, out)
    rpt = {'module': mod3, 'mode': 'static only; helper names are inferred roles', 'functions': hel2}
    (out / 'vendor-submit-helpers.json').write_text(json.dumps(rpt, indent=2) + '\n', encoding='utf-8')
    print('Dispatch table:', hex(tbl), len(ents2), 'entries;', len(sel), 'focused targets;', len(hel2), 'helpers')
    for f in hel2[-4:]:
        print('\n', f['name'], f['rva'], f['ops'], 'instructions')
        for edge in f['calls_and_tail_jumps']:
            if 'call' in edge['kind']:
                print(edge['site_rva'], edge['resolution'], edge['target'])
if __name__ == '__main__':
    main()
