# _pe_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
import os
from pathlib import Path
import struct as st2
import pefile as pef
from vx import ext3, prs_tbl, nam
root2 = Path(__file__).resolve().parents[1]
sha_256 = '6bfb39b635e6aa3ccb9b6b693b6e49575e4b2e4b35376a8fb037d58df146a77e'
hel = {1266096: 'LegacyQueryDispatch', 1611328: 'PStatesSubmitInternal', 2699296: 'PStatesPrecheckA', 2695424: 'PStatesPrecheckB', 2702928: 'PStatesPrecheckC', 2696576: 'PStatesPrecheckD', 1614912: 'NormalizedPStatesSubmit', 1613888: 'PStatesCapabilityRead', 2057984: 'PStatesInternalRead', 742192: 'AfterClockSubmit', 3750464: 'InternalControlTransport', 3751040: 'ControlForwarder', 3752032: 'ControlForwarderDispatch'}

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--helpers', action='store_true', help='Extract the audited helper map too')
    args = ap.parse_args()
    out = root2 / 'analysis/phase7'
    path = Path(os.environ['WINDIR']) / 'SysWOW64/nvapi.dll'
    if has2.sha256(path.read_bytes()).hexdigest() != sha_256:
        raise ValueError('Installed x86 NVAPI changed; re-audit pinned RVAs')
    core = json.loads((out / 'core-callgraph.json').read_text(encoding='utf-8'))
    sel3 = {int(x['literal'], 16) for b in core['dynamic_bindings'] for x in b['query_literals']}
    with pef.PE(str(path)) as pe:
        if pe.FILE_HEADER.Machine != 332:
            raise ValueError('Expected x86 NVAPI')
        base = pe.OPTIONAL_HEADER.ImageBase
        tbl = 5640192
        anc = pe.get_data(1266114, 6)
        if anc[:2] != b'9\x91' or st2.unpack('<I', anc[2:])[0] != base + tbl + 4:
            raise ValueError('x86 query table-reference instruction changed')
        ents2 = prs_tbl(pe, tbl, ptr_size=4)
        sel = [dict(e, name=nam.get(int(e['selector'], 16), 'Selector_' + format(int(e['selector'], 16), '08x'))) for e in ents2 if int(e['selector'], 16) in sel3 or int(e['selector'], 16) in nam]
        mod3 = {'path': str(path), 'sha256': sha_256, 'image_base': hex(base), 'machine': '0x14c', 'exports': [{'name': e['name'], 'rva': e['target_rva']} for e in sel], 'imports': [{'dll': m.dll.decode('ascii', 'replace'), 'name': i.name.decode('ascii', 'replace') if i.name else None, 'ordinal': i.ordinal, 'iat_va': hex(i.address)} for m in pe.DIRECTORY_ENTRY_IMPORT for i in m.imports]}
    r2 = root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe'
    fns2 = ext3(path, mod3, [{'name': e['name'], 'rva': int(e['target_rva'], 16)} for e in sel], r2, out, pre='SystemNVAPI32')
    for ent, fn in zip(sel, fns2):
        ent.update(fn)
    unr = [hex(s) for s in sorted(sel3) if not any((int(e['selector'], 16) == s for e in sel))]
    rpt = {'mode': 'static only; no target APIs executed', 'module': mod3, 'table_rva': hex(tbl), 'table_stride': 8, 'table_entries': len(ents2), 'query_export_rva': '0x138fd0', 'legacy_query_helper_rva': '0x1351b0', 'query_anchor_rva': '0x1351c2', 'selected_bindings': sel, 'unresolved_selectors': unr, 'limits': ['Loaded module identity observed separately; no live branch tracing.', 'QueryInterface includes conditional alternative dispatch paths.', 'Helper labels describe inferred roles, not original vendor symbols.']}
    (out / 'vendor32-dispatch.json').write_text(json.dumps(rpt, indent=2) + '\n', encoding='utf-8')
    print('X86 table', hex(tbl), len(ents2), 'entries; selected', len(sel))
    print('Bindings:', [(e['selector'], e['target_rva']) for e in sel])
    if args.helpers:
        hel2 = ext3(path, mod3, [{'name': name, 'rva': rva} for rva, name in hel.items()], r2, out, pre='SystemNVAPI32')
        data = {'mode': 'static only; inferred helper names', 'module': mod3, 'functions': hel2}
        (out / 'vendor32-submit-helpers.json').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    set2 = next((e for e in sel if int(e['selector'], 16) == 256749163))
    print('Setter calls:', [(e['site_rva'], e['instruction']) for e in set2['calls_and_tail_jumps'] if 'call' in e['kind']])
if __name__ == '__main__':
    main()
