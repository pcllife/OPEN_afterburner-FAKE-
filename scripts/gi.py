# _abi_
from pathlib import Path
import hashlib as has2, json, re
root2 = Path(__file__).resolve().parents[1]
sou = root2 / 'tools' / 'nvapi-headers'
fns = {'INIT': 'NvAPI_Initialize', 'UNLD': 'NvAPI_Unload', 'ENUM_GPU': 'NvAPI_EnumPhysicalGPUs', 'GET_NM': 'NvAPI_GPU_GetFullName', 'GET_DYN': 'NvAPI_GPU_GetDynamicPstatesInfoEx', 'GET_CLK': 'NvAPI_GPU_GetAllClockFrequencies', 'GET_THM': 'NvAPI_GPU_GetThermalSettings', 'GET_TACH': 'NvAPI_GPU_GetTachReading', 'GET_MEM': 'NvAPI_GPU_GetMemoryInfo', 'GET_DRV': 'NvAPI_SYS_GetDriverAndBranchVersion'}

def main():
    pro2 = json.loads((sou / 'sources.json').read_text())
    src2 = next((item for item in pro2['files'] if item['file'] == 'nvapi_interface.h'))
    data = (sou / 'nvapi_interface.h').read_bytes()
    assert has2.sha256(data).hexdigest() == src2['sha256'], 'Header hash changed'
    ide = {name: int(val, 16) for name, val in re.findall(b'\\{\\s*"([^"]+)"\\s*,\\s*(0x[0-9a-fA-F]+)\\s*\\}', data)}
    lin = ['// _abi_']
    for const, name in fns.items():
        assert '_Set' not in name
        val = ide[name.encode()]
        lin.append(f'pub const {const}: u32 = 0x{val:08x};')
    tgt = root2 / 'src' / 'ni.rs'
    tgt.write_text('\n'.join(lin) + '\n', encoding='utf-8')
    print('Generated', len(fns), 'read-only/lifecycle identifiers:', tgt)
if __name__ == '__main__':
    main()
