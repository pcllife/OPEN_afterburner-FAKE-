# _pe_
import ctypes as c
import hashlib as has2
import json
from pathlib import Path
root2 = Path(__file__).resolve().parents[1]
OUT = root2 / 'analysis/phase4'

class Poi(c.LittleEndianStructure):
    _fields_ = [('voltage_uv', c.c_uint32), ('frequency_khz', c.c_uint32), ('offset_khz', c.c_int32)]

class Tup(c.LittleEndianStructure):
    _fields_ = [('a', c.c_uint32), ('b', c.c_uint32), ('frequency_cur', c.c_uint32), ('frequency_def', c.c_uint32)]

class Cur(c.LittleEndianStructure):
    _fields_ = [('version', c.c_uint32), ('flags', c.c_uint32), ('points', c.c_uint32), ('vf', Poi * 256), ('lock_plus_one', c.c_uint32), ('power_count', c.c_uint32), ('power', Tup * 4), ('thermal_count', c.c_uint32), ('thermal', Tup * 4)]

class Ent(c.LittleEndianStructure):
    _fields_ = [('scalars', c.c_uint32 * 69), ('curve', Cur), ('gpu_id', c.c_char * 260)]

def main():
    rpt = json.loads((OUT / 'overclock-callgraph.json').read_text())

    def evi(rva, sit):
        item = next((f for f in rpt['functions'] if f['rva'] == rva))
        f = json.loads((OUT / (item['artifact_prefix'] + '.json')).read_text())
        base = 4194304 if item['module'] == 'MSIAfterburner.exe' else 268435456
        ops = {hex(op['offset'] - base): op['disasm'] for op in f['ops']}
        return {'function': item['name'], 'rva': rva, 'artifact_prefix': item['artifact_prefix'], 'instructions': [{'rva': site, 'text': ops[site]} for site in sit]}
    fin2 = [{'id': 'default_reset_stub', 'conclusion': 'NVIDIA SetDefaultClocks returns false; not a working reset mechanism.', 'evidence': evi('0x640a0', ['0x640a0', '0x640a2'])}, {'id': 'signed_frequency_offsets', 'conclusion': 'Bundled MACM clock offsets are signed LONG kHz; domains 0/4 select core/memory.', 'evidence': [evi('0x86060', ['0x86063', '0x86066', '0x86068']), evi('0x860d0', ['0x860d3', '0x860d6', '0x860d8'])]}, {'id': 'range_source', 'conclusion': 'NVIDIA range getter selects VF or PStates20 based on capability; absent data is not a guaranteed safe range.', 'evidence': evi('0x60db0', ['0x60de7', '0x60df9', '0x60e08', '0x60e14'])}, {'id': 'partial_failure_not_atomic', 'conclusion': 'Upper clock-offset method invokes memory setter after core setter without testing core return.', 'evidence': evi('0x63f30', ['0x64002', '0x64007', '0x64010', '0x64015'])}, {'id': 'pstates_local_no_range_query', 'conclusion': 'Narrow PStates20 setter builds one domain request and returns bool, without querying ranges inside this function.', 'evidence': evi('0x85fa0', ['0x85feb', '0x8601a', '0x86022', '0x86025', '0x86029'])}, {'id': 'power_scaling_and_status', 'conclusion': 'Power input is scaled by 1000 with unsigned policy boundary selections; final vendor status is not explicitly tested before void return.', 'evidence': evi('0x86f40', ['0x86fe5', '0x87017', '0x8701e', '0x87030', '0x87036', '0x8703b'])}, {'id': 'legacy_failure_returns_false', 'conclusion': 'Legacy absolute-clock submissions branch to false on error; no rollback of earlier hardware changes is established.', 'evidence': evi('0x86c70', ['0x86ea5', '0x86eac', '0x86ed2', '0x86ed9', '0x86f19'])}, {'id': 'vf_debug_mode_error', 'conclusion': 'VF setter tracks status -217 (GPU debug mode, OC not allowed) and returns false. No bypass is implemented.', 'evidence': evi('0x882b0', ['0x883ad', '0x883b9', '0x883c6', '0x883cd'])}, {'id': 'default_offset_zero', 'conclusion': 'PStates20 getter explicitly emits default offset zero after successful query; this is not a VBIOS backup.', 'evidence': evi('0x85ad0', ['0x85b3c', '0x85b43', '0x85b88'])}]
    sdk = root2 / 'afterb/MSI Afterburner/SDK/Include/MACMSharedMemory.h'
    lay = {'source': str(sdk.relative_to(root2)), 'sha256': has2.sha256(sdk.read_bytes()).hexdigest(), 'method': 'independent ctypes reconstruction using fixed-width fields from bundled SDK', 'macm_version': '0x00020003', 'header_bytes': 36, 'entry_bytes': c.sizeof(Ent), 'curve_offset': Ent.curve.offset, 'curve_bytes': c.sizeof(Cur), 'gpu_id_offset': Ent.gpu_id.offset, 'curve_points_max': 256, 'curve_tuples_max': 4, 'curve_fields': {name: getattr(Cur, name).offset for name, _ in Cur._fields_}}
    assert lay['entry_bytes'] == 3760 and lay['curve_bytes'] == 3224
    assert lay['curve_offset'] == 276 and lay['gpu_id_offset'] == 3500
    (OUT / 'macm-sdk-layout.json').write_text(json.dumps(lay, indent=2) + '\n')
    res4 = {'mode': 'static only; not a hardware stability or protection guarantee', 'hardware_setting_calls_executed': False, 'findings': fin2, 'live_range_capture': 'unavailable: MACMSharedMemory not present; producer not started', 'limitations': ['No live OC values collected or fabricated.', 'Static checks cannot certify safe/stable settings.', 'No voltage, power, frequency, thermal or fan setter exposed by the executable.', 'No automatic rollback or multi-parameter atomicity claim.']}
    (OUT / 'overclock-findings.json').write_text(json.dumps(res4, indent=2) + '\n')
    print(len(fin2), 'findings; SDK entry=', lay['entry_bytes'], 'curve=', lay['curve_bytes'])
if __name__ == '__main__':
    main()
