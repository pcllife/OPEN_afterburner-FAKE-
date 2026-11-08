# _io_
import ctypes as C
import json, os, time
from pathlib import Path

def rd_json(path):
    path = Path(path)
    if os.name != 'nt':
        return json.loads(path.read_text(encoding='utf-8-sig'))
    import msvcrt as msv
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [C.c_wchar_p, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p]
    k.CreateFileW.restype = C.c_void_p
    k.CloseHandle.argtypes = [C.c_void_p]
    h = k.CreateFileW(str(path.resolve()), 2147483648, 7, None, 3, 128, None)
    if h == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        fd = msv.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        k.CloseHandle(h)
        raise
    with os.fdopen(fd, 'r', encoding='utf-8-sig') as str2:
        return json.load(str2)

def ato_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    for att in range(6):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if att == 5:
                raise
            time.sleep(0.01 * (att + 1))
