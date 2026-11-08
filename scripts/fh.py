# _abi_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
from pathlib import Path
import re
from urllib.request import Request as req, urlopen as url2
root2 = Path(__file__).resolve().parents[1]
OUT = root2 / 'tools' / 'nvapi-headers'
fil = ('nvapi.h', 'nvapi_interface.h', 'nvapi_lite_common.h')

def get(url: str) -> tuple[bytes, str]:
    tra2 = [url]
    if 'raw.githubusercontent.com/NVIDIA/nvapi/' in url:
        rev, fnm = url.split('/NVIDIA/nvapi/', 1)[1].split('/', 1)
        tra2.append(f'https://cdn.jsdelivr.net/gh/NVIDIA/nvapi@{rev}/{fnm}')
    tra2.append('https://gh-proxy.com/' + url)
    errs = []
    for tra in tra2:
        try:
            req2 = req(tra, headers={'User-Agent': 'Afterburner-static-research'})
            with url2(req2, timeout=15) as rsp:
                return (rsp.read(), tra)
        except Exception as exc:
            errs.append(f'{tra}: {exc}')
    raise RuntimeError('; '.join(errs))

def ver_cac(dir2: Path) -> dict:
    rpt = json.loads((dir2 / 'sources.json').read_text(encoding='utf-8'))
    com4 = rpt.get('commit', '')
    if not re.fullmatch('[0-9a-f]{40}', com4):
        raise ValueError('Header manifest must identify an exact NVIDIA/nvapi commit')
    if {item['file'] for item in rpt['files']} != set(fil):
        raise ValueError('Incomplete NVIDIA header cache')
    for item in rpt['files']:
        if item['source'] != f"https://raw.githubusercontent.com/NVIDIA/nvapi/{com4}/{item['file']}":
            raise ValueError('Unexpected header source')
        data = (dir2 / item['file']).read_bytes()
        if len(data) != item['bytes'] or has2.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Cached header changed: ' + item['file'])
    return rpt

def main() -> None:
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--refresh', action='store_true')
    ap.add_argument('--commit', help='Exact NVIDIA/nvapi commit; not a branch name')
    args = ap.parse_args()
    if not args.refresh and (not args.commit) and (OUT / 'sources.json').is_file():
        rpt = ver_cac(OUT)
        print('Verified pinned NVIDIA header cache:', rpt['commit'])
        return
    com4, md_src, md_tra = (args.commit, None, None)
    if com4 is None:
        md_src = 'https://api.github.com/repos/NVIDIA/nvapi/commits/main'
        md, md_tra = get(md_src)
        com4 = json.loads(md)['sha']
    if not re.fullmatch('[0-9a-f]{40}', com4):
        ap.error('--commit must be an exact 40-character lowercase Git SHA')
    rpt = {'repository': 'https://github.com/NVIDIA/nvapi', 'commit': com4, 'commit_metadata_source': md_src, 'commit_metadata_transport': md_tra, 'files': []}
    dow = {}
    for fnm in fil:
        url = f'https://raw.githubusercontent.com/NVIDIA/nvapi/{com4}/{fnm}'
        data, via = get(url)
        if b'NVIDIA' not in data or len(data) < 1000:
            raise ValueError('Header validation failed: ' + fnm)
        dow[fnm] = data
        rpt['files'].append({'file': fnm, 'source': url, 'transport': via, 'bytes': len(data), 'sha256': has2.sha256(data).hexdigest()})
    OUT.mkdir(parents=True, exist_ok=True)
    for fnm, data in dow.items():
        (OUT / fnm).write_bytes(data)
    (OUT / 'sources.json').write_text(json.dumps(rpt, indent=2) + '\n', encoding='utf-8')
    ver_cac(OUT)
    print('Cached pinned NVIDIA headers:', com4)
if __name__ == '__main__':
    main()
