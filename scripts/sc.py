# _pe_
from __future__ import annotations
import hashlib as has2
import json
import re
from pathlib import Path
root2 = Path(__file__).resolve().parents[1]
pha = root2 / 'analysis/phase7'

def load(name):
    return json.loads((pha / name).read_text(encoding='utf-8'))

def bui():
    core = load('core-callgraph.json')
    ven_64 = load('vendor-dispatch.json')
    hel_64 = load('vendor-submit-helpers.json')
    ven_32 = load('vendor32-dispatch.json')
    hel_32 = load('vendor32-submit-helpers.json')
    gro2 = {'rthal': core['functions'], 'nvapi32': ven_32['selected_bindings'] + hel_32['functions'], 'nvapi64': ven_64['selected_bindings'] + hel_64['functions']}
    bas = {'rthal': 268435456, 'nvapi32': 268435456, 'nvapi64': 6442450944}
    cla = []

    def evi(key, gro, rva, nee2, mea):
        item = next((x for x in gro2[gro] if int(x['rva'], 16) == rva))
        art = pha / (item['artifact_prefix'] + '.json')
        raw = json.loads(art.read_text(encoding='utf-8'))
        sit = []
        for req4 in nee2:
            exa_rva, nee = req4 if isinstance(req4, tuple) else (None, req4)

            def mat2(op):
                nor = re.sub('\\bfcn\\.([0-9a-f]+)\\b', '0x\\1', op.get('disasm', ''))
                return nee in nor and (exa_rva is None or op['offset'] - bas[gro] == exa_rva)
            op = next((o for o in raw['ops'] if mat2(o)), None)
            if op is None:
                raise ValueError(f'Evidence missing: {key}: {nee}')
            sit.append({'rva': hex(op['offset'] - bas[gro]), 'instruction': op['disasm'], 'bytes': op.get('bytes'), 'matched': nee})
        cla.append({'id': key, 'module': gro, 'function_rva': hex(rva), 'function_label': item['name'], 'artifact': art.relative_to(root2).as_posix(), 'artifact_sha256': has2.sha256(art.read_bytes()).hexdigest(), 'evidence_type': 'static instructions; branch execution not observed', 'interpretation': mea, 'sites': sit})
    evi('x86.accepted_versions', 'nvapi32', 2065440, ['cmp ecx, 0x11c94', 'cmp ecx, 0x21cf8', 'cmp ecx, 0x31cf8', 'call 0x10189640'], 'The x86 PStates setter accepts these complete structure versions before the internal helper.')
    evi('x86.editability_and_signed_bounds', 'nvapi32', 1611328, [(1612400, 'test byte [eax + 0x18], 1'), (1612505, 'test byte [esi + 8], 1'), (1612551, 'cmp ebx, eax'), (1612553, 'jg 0x10189ec9'), (1612582, 'cmp ebx, eax'), (1612584, 'jl 0x10189ec9')], 'The internal setter tests editability and branches on signed bounds; this does not establish safe limits.')
    evi('x86.normalization', 'nvapi32', 1611328, ['imul eax, dword [esi + 0xc], 0x64', 'idiv ebx', 'mov dword [ebx], 0x23d98', 'call 0x1018a440'], 'A requested clock delta is scaled by 100 and divided by the capability multiplier before normalized submission.')
    evi('x86.transport_packet', 'nvapi32', 1614912, ['add edx, 0x7c8', 'push 0x7f0c', 'push 0x700016a', 'call 0x10393a40'], 'The transport packet is 0x7f0c bytes with 0x7c8 state stride; 0x0700016a is an internal operation, not the Win32 IOCTL.')
    evi('x86.transport_forward', 'nvapi32', 3750464, ['call 0x10393c80'], 'Internal control reaches a forwarder with conditional transport alternatives.')
    evi('x86.admin_envelope', 'nvapi32', 3751040, ['mov dword [edi], 0x4e564441', 'mov dword [edi + 4], 0x10002', 'push 0x8de0008', 'push 0x8de0010', 'call 0x10394060'], 'Conditional admin routes package a signature/version and use two distinct IOCTL codes.')
    evi('x86.device_boundary', 'nvapi32', 3752032, ['push str..NvAdminDevice', 'KERNEL32.dll_CreateFileA', 'KERNEL32.dll_DeviceIoControl'], 'The identified admin branch opens NvAdminDevice and reaches DeviceIoControl. Kernel internals are outside this evidence.')
    evi('x64.accepted_versions', 'nvapi64', 2281712, ['cmp eax, 0x11c94', 'cmp eax, 0x21cf8', 'cmp eax, 0x31cf8', 'call 0x1801b2330'], 'Equivalent selector implementation in x64, retained for comparison rather than substituted into the x86 process.')
    evi('x64.signed_clock_bounds', 'nvapi64', 1778480, [(1779755, 'cmp r10d, edx'), (1779758, 'jg 0x1801b2c60'), (1779787, 'cmp r10d, edx'), (1779790, 'jl 0x1801b2c60'), 'idiv r10d', 'call 0x1801b3400'], 'x64 corroborates signed checking and capability-dependent normalized scaling.')
    evi('x64.transport_packet', 'nvapi64', 1782784, ['mov r8d, 0x7f0c', 'mov ecx, 0x700016a', 'call 0x1803fca00'], 'x64 uses the same internal operation ID and expanded payload size.')
    evi('x64.device_boundary', 'nvapi64', 4182000, ['KERNEL32.dll_CreateFileA', 'KERNEL32.dll_DeviceIoControl'], 'The x64 comparison also has a conditional admin device boundary, not proof of an executing route.')
    evi('rthal.voltage_backend', 'rthal', 412256, ['VFCurve_IsSupported', 'ClientVoltageRail_SetControl', 'PS20_SetCoreVoltageBoost'], 'Voltage control routes to distinct VF/rail and PStates backends depending on capability.')
    evi('rthal.voltage_pstates_route', 'rthal', 548992, ['PS20_IsRelVoltageSupported', 'PS20_SetRelVoltageBoost', 'PS20_SetVoltageBoost'], 'PStates voltage requests select the OV extension or per-state base-voltage delta route.')
    evi('rthal.relative_voltage_units', 'rthal', 549104, ['imul ecx, dword [ebp + 0xc], 0x3e8', '0x21cf8'], 'The PStates relative-voltage wrapper converts mV input to microvolts.')
    evi('rthal.base_voltage_units', 'rthal', 549360, ['imul eax, dword [ebp + 0xc], 0x3e8', '0x11c94'], 'The per-state voltage wrapper separately converts mV input to microvolts.')
    evi('rthal.rail_byte_control', 'rthal', 530576, ['mov al, byte [ebp + 8]', 'mov byte [ebp - 0x28], al', '0x10028'], 'The rail wrapper puts only the low input byte in a 40-byte packet; its units are not established as mV.')
    cha2 = {}
    for gro, rvas in {'rthal': [548768, 526176, 39632], 'nvapi32': [2065440, 1611328, 1614912, 3750464, 3751040, 3752032], 'nvapi64': [2281712, 1778480, 1782784, 4180480, 4181024, 4182000]}.items():
        cha = []
        for src, dst in zip(rvas, rvas[1:]):
            item = next((x for x in gro2[gro] if int(x['rva'], 16) == src))
            edg = [e for e in item['calls_and_tail_jumps'] if e.get('target_va') and int(e['target_va'], 16) - bas[gro] == dst]
            if not edg:
                raise ValueError(f'Missing direct edge {gro} {src:#x}->{dst:#x}')
            cha.append({'source_rva': hex(src), 'target_rva': hex(dst), 'sites': edg})
        cha2[gro] = cha
    bin2 = []
    for ent in ven_32['selected_bindings']:
        oth = next((e for e in ven_64['selected_bindings'] if e['selector'] == ent['selector']))
        bin2.append({'selector': ent['selector'], 'x86_target_rva': ent['target_rva'], 'x64_target_rva': oth['target_rva']})
    return {'mode': 'static evidence consolidation; no target code executed or hardware writes', 'sources': {'rthal': core['module'], 'nvapi32': {k: ven_32['module'][k] for k in ['path', 'sha256', 'image_base', 'machine']}, 'nvapi64': {k: ven_64['module'][k] for k in ['path', 'sha256', 'image_base']}}, 'scope': {'rthal_functions': len(core['functions']), 'rthal_thunks': len(core['dynamic_bindings']), 'selected_bindings_per_architecture': len(bin2), 'dispatch_entries_x86': ven_32['table_entries'], 'dispatch_entries_x64': ven_64['table_entries'], 'helpers_x86': len(hel_32['functions']), 'helpers_x64': len(hel_64['functions'])}, 'architecture': {'afterburner': 'x86', 'rthal': 'x86', 'loaded_vendor_module': 'nvapi32', 'module_observation': 'analysis/phase7/process-modules-readonly.json', 'live_branch_traced': False, 'nvapi64_role': "static comparison, not the app's loaded NVAPI"}, 'selector_bindings': bin2, 'direct_call_chains': cha2, 'claims': cla, 'limits': ['The recovered tables belong to conditional legacy QueryInterface paths.', 'A loaded module and a static call graph do not establish live branch execution.', 'DeviceIoControl is the recovered user/kernel boundary, not recovered kernel internals.', 'No nvlddmkm kernel implementation, GPU register programming or firmware execution is established.', 'No live setters, voltage adjustments, automatic rollback or stability qualification occur in this phase.']}

def main():
    res4 = bui()
    (pha / 'overclock-core-findings.json').write_text(json.dumps(res4, indent=2) + '\n', encoding='utf-8')
    print('Verified', len(res4['claims']), 'instruction-backed findings and', sum((len(v) for v in res4['direct_call_chains'].values())), 'direct call edges')
if __name__ == '__main__':
    main()
