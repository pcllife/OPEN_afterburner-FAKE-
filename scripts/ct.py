# _pe_
import hashlib as has2
import json
from pathlib import Path
import re
import pefile as pef
root2 = Path(__file__).resolve().parents[1]
pha_7 = root2 / 'analysis/phase7'
OUT = root2 / 'analysis/phase8/clock-call-contract.json'
rth_sha_256 = '08c6d92cf91a3c73228c874bba6f402e6ae6b63a70fb0f55eca823b197885f4c'
BASE = 268435456

def bui_con():
    fil2 = {'clock': 'RTHAL-CNVAPIWrapper.PS20_SetClockBoost-85fa0.json', 'graphics': 'RTHAL-CNVAPIWrapper.PS20_SetCoreClockBoost-86060.json', 'memory': 'RTHAL-CNVAPIWrapper.PS20_SetMemoryClockBoost-860d0.json', 'interface': 'RTHAL-CNVAPIInterface.GpuSetPstates20-80760.json'}
    loa2 = {key: json.loads((pha_7 / name).read_text(encoding='utf-8')) for key, name in fil2.items()}
    evi = []

    def chk(gro, rva, ins2):
        op = next((o for o in loa2[gro]['ops'] if o['offset'] - BASE == rva), None)
        if op is None or op.get('disasm') != ins2:
            raise ValueError(f'Instruction mismatch at {rva:#x}: expected {ins2}')
        item = {'artifact': 'analysis/phase7/' + fil2[gro], 'rva': hex(rva), 'instruction': ins2, 'bytes': op['bytes']}
        evi.append(item)
        return op

    def fie(name, rva, ins2, val, kind='uint32'):
        chk('clock', rva, ins2)
        mat = re.fullmatch('mov dword \\[ebp - (0x[0-9a-f]+)\\], .+', ins2)
        if not mat:
            raise ValueError('Expected an audited stack-buffer store')
        off2 = 7320 - int(mat[1], 16)
        if not 0 <= off2 <= 7312:
            raise ValueError('Store is outside the zeroed request buffer')
        return {'name': name, 'offset': off2, 'type': kind, 'value': val, 'evidence_rva': hex(rva)}
    chk('clock', 548792, 'push 0x1c94')
    chk('clock', 548797, 'lea eax, [ebp - 0x1c98]')
    chk('clock', 548805, 'push 0')
    chk('clock', 548808, 'call sub.VCRUNTIME140.dll_memset')
    chk('clock', 548813, 'mov eax, dword [ebp + 8]')
    chk('clock', 548828, 'mov eax, dword [ebp + 0xc]')
    fie2 = [fie('version', 548843, 'mov dword [ebp - 0x1c98], 0x11c94', '0x11c94'), fie('numPstates', 548860, 'mov dword [ebp - 0x1c90], 1', 1), fie('numClocks', 548870, 'mov dword [ebp - 0x1c8c], 1', 1), {'name': 'numBaseVoltages', 'offset': 16, 'type': 'uint32', 'value': 0, 'evidence': '7316-byte zero initialization; no subsequent store to this field'}, fie('pstates[0].pstateId', 548880, 'mov dword [ebp - 0x1c84], 0', 0), fie('pstates[0].clocks[0].domainId', 548822, 'mov dword [ebp - 0x1c7c], eax', 'argument 1'), fie('pstates[0].clocks[0].freqDelta_kHz.value', 548831, 'mov dword [ebp - 0x1c70], eax', 'argument 2, copied without scaling', 'int32')]
    chk('graphics', 548966, 'push 0')
    chk('memory', 549078, 'push 4')
    chk('clock', 548854, 'push dword [esi + 0x420]')
    chk('clock', 548898, 'neg eax')
    chk('clock', 548901, 'sbb eax, eax')
    chk('clock', 548905, 'inc eax')
    chk('clock', 548914, 'ret 8')
    chk('interface', 526179, 'push dword [ebp + 0xc]')
    chk('interface', 526182, 'push dword [ebp + 8]')
    chk('interface', 526190, 'add esp, 8')
    chk('interface', 526194, 'ret 8')
    core = json.loads((pha_7 / 'core-callgraph.json').read_text(encoding='utf-8'))
    thu = next((x for x in core['dynamic_bindings'] if x['thunk_rva'] == '0x9ad0'))
    sel3 = {int(x['literal'], 16) for x in thu['query_literals']}
    if sel3 != {256749163}:
        raise ValueError('Unexpected selector binding')
    bin2 = {}
    for arch, name in [('x86', 'vendor32-dispatch.json'), ('x64_comparison', 'vendor-dispatch.json')]:
        rpt = json.loads((pha_7 / name).read_text(encoding='utf-8'))
        mat = next((x for x in rpt['selected_bindings'] if int(x['selector'], 16) == 256749163))
        bin2[arch] = {'module_sha256': rpt['module']['sha256'], 'target_rva': mat['target_rva']}
    return {'schema': 'afterburner.pstates20.clock-contract.v1', 'mode': 'offline specification; no invocation implemented', 'scope': ['P0 graphics clock delta', 'P0 memory clock delta'], 'rthal_module_sha256': rth_sha_256, 'wrapper': {'rva': '0x85fa0', 'name': 'CNVAPIWrapper::PS20_SetClockBoost', 'calling_convention': 'x86 member __thiscall; object in ECX; two stack arguments; ret 8', 'arguments': ['domain_id: uint32', 'delta_khz: int32'], 'gpu_handle': 'selected opaque handle read from wrapper object +0x420 in this build only', 'return': 'int boolean: raw NVAPI status 0 becomes 1; any nonzero status becomes 0'}, 'vendor': {'selector': '0xf4dae6b', 'query_thunk_rva': '0x9ad0', 'signature': 'int32 status (opaque physical-GPU handle, pointer to PStates20 buffer)', 'x86_calling_convention': 'caller-cleans-stack (__cdecl), unlike the RTHAL member wrapper', 'success_status': 0, 'bindings': bin2, 'pointer_rules': ['A GPU handle belongs to the live API instance, not a serializable stable identity.', 'Pointers and calling process must match the chosen DLL architecture.', 'The packet contains no GPU identity or hardware handle.']}, 'request': {'structure': 'NV_GPU_PERF_PSTATES20_INFO_V1', 'version': '0x11c94', 'bytes': 7316, 'initialization': 'zero entire 7316-byte structure before populating listed fields', 'domains': {'graphics': 0, 'memory': 4}, 'delta_units': 'signed kHz, no scaling in this wrapper', 'fields': fie2}, 'evidence': evi, 'future_live_sequence_not_implemented': ['Initialize the matching vendor API and select a GPU by externally recorded stable identity.', 'Read current capabilities and save original control deltas; do not assume the original value is zero.', 'Construct one narrow request; preserve raw vendor error status instead of using a boolean alone.', 'If explicitly enabled later, submit once and independently read the selected target and non-target controls.', 'Any later restore must target the recorded original value and verify a fresh readback; no automatic recovery is established.'], 'constraints': ['Only this observed narrow P0 request shape is implemented.', 'All unspecified bytes remain zero; do not copy a getter buffer into the request.', 'No effective-memory-data-rate conversion is inferred.', 'No voltage, VF curve, power, temperature or fan request is implemented.', "The x64 implementation is comparison evidence, not the x86 application's loaded module.", 'Static legacy dispatch bindings are not proof of the currently executing query branch.', 'Observed matching control fields do not prove hardware stability, physical voltage constancy or successful recovery.']}

def ver_src(con2):
    path = root2 / 'afterb/MSI Afterburner/RTHAL.dll'
    if has2.sha256(path.read_bytes()).hexdigest() != con2['rthal_module_sha256']:
        raise ValueError('RTHAL sample changed')
    with pef.PE(str(path), fast_load=True) as pe:
        for site in con2['evidence']:
            raw = bytes.fromhex(site['bytes'])
            if pe.get_data(int(site['rva'], 16), len(raw)) != raw:
                raise ValueError('Source bytes do not match evidence at ' + site['rva'])
    return len(con2['evidence'])

def main():
    con2 = bui_con()
    cou = ver_src(con2)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(con2, indent=2) + '\n', encoding='utf-8')
    print('Derived', len(con2['request']['fields']), 'request fields; verified', cou, 'instruction sites')
if __name__ == '__main__':
    main()
