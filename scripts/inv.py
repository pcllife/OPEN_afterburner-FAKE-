# _pe_
from __future__ import annotations
import argparse as arg
import hashlib as has2
import json
from pathlib import Path
import re
import capstone as cap
from capstone.x86_const import X86_OP_MEM as x_86_op_mem, X86_REG_RIP as x_86_reg_rip
import pefile as pef
root2 = Path(__file__).resolve().parents[1]
core_nam = ('MSIAfterburner.exe', 'RTCore.dll', 'RTHAL.dll', 'RTFC.dll', 'RTCore32.sys', 'RTCore64.sys', 'Plugins/Monitoring/GPU.dll', 'Plugins/Monitoring/CPU.dll', 'Plugins/Monitoring/PerfCounter.dll', 'Bundle/OCScanner/MSIOCScanner_x64.exe', 'Bundle/OCScanner/scanner.dll')
asc = re.compile(b'[\\x20-\\x7e]{4,}')
utf_16 = re.compile(b'(?:[\\x20-\\x7e]\\x00){4,}')
int2 = re.compile('RTCore|RTHAL|NVAPI|nvapi|ADL_|atiadl|Overdrive|D3DKMT|D3D.*Query|MAHM|MACM|SharedMemory|DeviceIoControl|\\\\Device\\\\|\\\\DosDevices\\\\|Clock|Voltage|PowerLimit|Pstate|Usage|Utilization|ReadMSR|WriteMSR|ReadBusData|WriteBusData|ReadRegister|WriteRegister|I2C|GetSystemTimes|QueryPerformance|NtQuerySystem|Pdh|GPU Engine', re.I)
pri = {'in', 'out', 'insb', 'insd', 'insw', 'outsb', 'outsd', 'outsw', 'rdmsr', 'wrmsr', 'cli', 'sti', 'invlpg'}

def dec(val: bytes | None) -> str | None:
    return val.decode('utf-8', errors='replace') if val is not None else None

def num(val: int) -> str:
    return hex(val)

def ver6(pe: pef.PE) -> dict[str, str]:
    res4 = {}
    for gro in getattr(pe, 'FileInfo', []):
        for blo in gro:
            for tbl in getattr(blo, 'StringTable', []):
                res4.update({dec(k): dec(v) for k, v in tbl.entries.items()})
    return res4

def imp3(pe: pef.PE) -> list[dict]:
    res4 = []
    for dir2, kind in [('DIRECTORY_ENTRY_IMPORT', 'normal'), ('DIRECTORY_ENTRY_DELAY_IMPORT', 'delay')]:
        for mod3 in getattr(pe, dir2, []):
            for sym3 in mod3.imports:
                res4.append({'dll': dec(mod3.dll), 'name': dec(sym3.name), 'ordinal': sym3.ordinal, 'iat_va': num(sym3.address), 'kind': kind})
    return res4

def str_evi(data: bytes, pe: pef.PE) -> list[dict]:
    res4 = []
    for pat3, enc in [(asc, 'ascii'), (utf_16, 'utf-16-le')]:
        for mat in pat3.finditer(data):
            text = mat.group().decode(enc)
            if not int2.search(text):
                continue
            try:
                rva = num(pe.get_rva_from_offset(mat.start()))
            except pef.PEFormatError:
                rva = None
            res4.append({'file_offset': num(mat.start()), 'rva': rva, 'encoding': enc, 'text': text})
    return sorted(res4, key=lambda item: int(item['file_offset'], 16))

def dri_ass(pe: pef.PE, ents2: list[dict]) -> tuple[str, list[dict]]:
    mode = cap.CS_MODE_64 if pe.FILE_HEADER.Machine == 34404 else cap.CS_MODE_32
    eng = cap.Cs(cap.CS_ARCH_X86, mode)
    eng.detail = True
    eng.skipdata = True
    ima_base = pe.OPTIONAL_HEADER.ImageBase
    sym4 = {int(item['iat_va'], 16): f"{item['dll']}!{item['name'] or item['ordinal']}" for item in ents2}
    lin = ['; Linear sweep only. Data bytes and unreachable instructions may be included.', f'; ImageBase={ima_base:#x}; Entry RVA={pe.OPTIONAL_HEADER.AddressOfEntryPoint:#x}']
    pri2 = []
    for sec4 in pe.sections:
        if not sec4.Characteristics & 536870912:
            continue
        name = dec(sec4.Name.rstrip(b'\x00'))
        lin.append(f'\n; Section {name}')
        code = sec4.get_data()[:min(sec4.Misc_VirtualSize, sec4.SizeOfRawData)]
        for ins in eng.disasm(code, ima_base + sec4.VirtualAddress):
            com3 = []
            if ins.id != 0:
                for ope in ins.operands:
                    if ope.type == x_86_op_mem:
                        mem = ope.mem
                        addr = ins.address + ins.size + mem.disp if mem.base == x_86_reg_rip else mem.disp if mem.base == 0 and mem.index == 0 else None
                        if addr in sym4:
                            com3.append(sym4[addr])
                if ins.mnemonic in pri:
                    pri2.append({'rva': num(ins.address - ima_base), 'mnemonic': ins.mnemonic, 'operands': ins.op_str, 'section': name, 'evidence': 'linear-sweep candidate'})
            suf = ' ; ' + ', '.join(com3) if com3 else ''
            lin.append(f'{ins.address:016x}  {ins.bytes.hex():24s} {ins.mnemonic:8s} {ins.op_str}{suf}')
    return ('\n'.join(lin) + '\n', pri2)

def ana(path: Path, base: Path, out: Path) -> dict:
    data = path.read_bytes()
    pe = pef.PE(data=data, fast_load=False)
    try:
        imp2 = imp3(pe)
        exp3 = [{'name': dec(sym.name), 'ordinal': sym.ordinal, 'rva': num(sym.address), 'forwarder': dec(sym.forwarder)} for sym in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])]
        info = {'path': path.relative_to(base).as_posix(), 'bytes': len(data), 'sha256': has2.sha256(data).hexdigest(), 'machine': num(pe.FILE_HEADER.Machine), 'architecture': {332: 'x86', 34404: 'x64'}.get(pe.FILE_HEADER.Machine, 'other'), 'image_base': num(pe.OPTIONAL_HEADER.ImageBase), 'entry_rva': num(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 'subsystem': pe.OPTIONAL_HEADER.Subsystem, 'coff_timestamp_raw': pe.FILE_HEADER.TimeDateStamp, 'version_resources': ver6(pe), 'sections': [{'name': dec(s.Name.rstrip(b'\x00')), 'rva': num(s.VirtualAddress), 'virtual_size': s.Misc_VirtualSize, 'raw_size': s.SizeOfRawData, 'entropy': round(s.get_entropy(), 4), 'characteristics': num(s.Characteristics)} for s in pe.sections], 'imports': imp2, 'exports': exp3, 'strings': str_evi(data, pe), 'parse_warnings': pe.get_warnings()}
        if path.suffix.lower() == '.sys':
            ass, can = dri_ass(pe, imp2)
            asm_name = path.name + '.linear.asm'
            (out / asm_name).write_text(ass, encoding='utf-8')
            info['assembly_report'] = asm_name
            info['privileged_instruction_candidates'] = can
        return info
    finally:
        pe.close()

def main() -> None:
    ap = arg.ArgumentParser(description=__doc__)
    ap.add_argument('--base', type=Path, default=root2 / 'afterb' / 'MSI Afterburner')
    ap.add_argument('--out', type=Path, default=root2 / 'analysis' / 'inventory')
    args = ap.parse_args()
    base, out = (args.base.resolve(), args.out.resolve())
    if not base.is_dir():
        ap.error(f'Sample directory does not exist: {base}')
    if out == base or base in out.parents:
        ap.error('Output must be outside the sample directory')
    out.mkdir(parents=True, exist_ok=True)
    rpt = {'sample_directory': str(base), 'method': 'static; no binaries executed', 'pefile_version': pef.__version__, 'capstone_version': cap.__version__, 'modules': [], 'missing': []}
    for name in core_nam:
        path = base / name
        if not path.is_file():
            rpt['missing'].append(name)
            continue
        info = ana(path, base, out)
        rpt['modules'].append(info)
        print(f"{info['path']}: {info['architecture']}, {len(info['imports'])} imports, {len(info['exports'])} exports, {len(info['strings'])} string hits")
    (out / 'pe_inventory.json').write_text(json.dumps(rpt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Report: {out / 'pe_inventory.json'}")
if __name__ == '__main__':
    main()
