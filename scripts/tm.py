# _pe_
from pathlib import Path
import argparse as arg, hashlib as has2, json, subprocess as sub2
from tr import prs_json_str, call_edg, asm_text
root2 = Path(__file__).resolve().parents[1]
BASE = root2 / 'afterb' / 'MSI Afterburner'
OUT = root2 / 'analysis' / 'phase3'
R2 = root2 / 'tools/r2/radare2-5.9.8-w64/bin/radare2.exe'
def2 = [393657, 345744, 332546, 329557, 392301, 394243, 389749, 384277, 358250, 415857, 341907, 349500, 358745, 364578, 348553, 348393, 74967, 75666, 345716, 345676, 72745]

def main():
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--rva', action='append', type=lambda val: int(val, 0), default=[])
    args = ap.parse_args()
    inv = json.loads((root2 / 'analysis/inventory/pe_inventory.json').read_text())
    mod3 = next((item for item in inv['modules'] if item['path'] == 'MSIAfterburner.exe'))
    path = BASE / mod3['path']
    if has2.sha256(path.read_bytes()).hexdigest() != mod3['sha256']:
        raise RuntimeError('MSIAfterburner sample changed since inventory')
    OUT.mkdir(parents=True, exist_ok=True)
    base = int(mod3['image_base'], 16)
    addrs = sorted(set(def2 + args.rva))
    com2 = 'aaa;' + ';'.join((f'af-*;af @ {base + rva:#x};pdfj @ {base + rva:#x}' for rva in addrs))
    proc = sub2.run([str(R2), '-2', '-q', '-e', 'scr.color=false', '-c', com2, str(path)], capture_output=True, check=True, timeout=120)
    fns2 = prs_json_str(proc.stdout.decode('utf-8', 'replace'))
    assert len(fns2) == len(addrs)
    rpt = {'module': mod3['path'], 'sha256': mod3['sha256'], 'image_base': hex(base), 'method': 'static recovery; internal names are inferred roles, not original symbols', 'functions': []}
    for rva, fn in zip(addrs, fns2):
        edg = call_edg(fn, mod3)
        stem = f'MSIAfterburner-rva-{rva:x}'
        (OUT / (stem + '.json')).write_text(json.dumps(fn, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        (OUT / (stem + '.asm')).write_text(asm_text(fn, mod3, {'name': hex(rva), 'rva': rva}, edg), encoding='utf-8')
        info = {'rva': hex(rva), 'reported_function_start': hex(fn.get('addr', base + rva) - base), 'ops': len(fn.get('ops', [])), 'artifact_prefix': stem, 'calls_and_tail_jumps': edg}
        rpt['functions'].append(info)
        print('\n--- RVA', hex(rva), '---')
        for edge in edg:
            if 'call' in edge['kind'] and (edge['resolution'] == 'iat' and 'RTHAL.dll!' in edge['target'] or rva in [329557, 393657, 384277]):
                print(edge['site_rva'], edge['resolution'], edge['target'])
    (OUT / 'macm-callgraph.json').write_text(json.dumps(rpt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
