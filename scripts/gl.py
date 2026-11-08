# _gl_
from __future__ import annotations
import argparse as arg, ctypes as C, hashlib as has2, json, math, os, struct as st2, sys, time, zlib
from pathlib import Path
wid, hei, FPS = (1280, 720, 60)
mod = ('geometry', 'texture', 'fragment')

class GlErr(RuntimeError):
    pass
from jio import ato_json as ato, rd_json

def save_png(path, rgba):

    def chu(name, data):
        return st2.pack('>I', len(data)) + name + data + st2.pack('>I', zlib.crc32(name + data) & 4294967295)
    rows = b''.join((b'\x00' + rgba[y * wid * 4:(y + 1) * wid * 4] for y in range(hei - 1, -1, -1)))
    Path(path).write_bytes(b'\x89PNG\r\n\x1a\n' + chu(b'IHDR', st2.pack('>IIBBBBB', wid, hei, 8, 6, 0, 0, 0)) + chu(b'IDAT', zlib.compress(rows, 3)) + chu(b'IEND', b''))

class Pfd(C.Structure):
    _fields_ = [('size', C.c_ushort), ('version', C.c_ushort), ('flags', C.c_uint), ('pixel_type', C.c_ubyte), ('color_bits', C.c_ubyte), ('red_bits', C.c_ubyte), ('red_shift', C.c_ubyte), ('green_bits', C.c_ubyte), ('green_shift', C.c_ubyte), ('blue_bits', C.c_ubyte), ('blue_shift', C.c_ubyte), ('alpha_bits', C.c_ubyte), ('alpha_shift', C.c_ubyte), ('accum_bits', C.c_ubyte), ('accum_red', C.c_ubyte), ('accum_green', C.c_ubyte), ('accum_blue', C.c_ubyte), ('accum_alpha', C.c_ubyte), ('depth_bits', C.c_ubyte), ('stencil_bits', C.c_ubyte), ('aux_buffers', C.c_ubyte), ('layer_type', C.c_ubyte), ('reserved', C.c_ubyte), ('layer_mask', C.c_uint), ('visible_mask', C.c_uint), ('damage_mask', C.c_uint)]
assert C.sizeof(Pfd) == 40
ver3 = '#version 120\nattribute vec2 position; attribute vec3 color;\nvarying vec2 uv; varying vec3 vcolor;\nvoid main(){uv=position*0.5+0.5;vcolor=color;gl_Position=vec4(position,0.0,1.0);}\n'
fra = {'geometry': '#version 120\nvarying vec3 vcolor; void main(){gl_FragColor=vec4(vcolor,1.0);}\n', 'texture': '#version 120\nvarying vec2 uv; uniform sampler2D image;\nvoid main(){vec3 c=vec3(0.0);for(int i=0;i<24;i++){\nvec2 p=uv*(2.0+float(i)*0.19)+vec2(float(i)*0.037,float(i)*0.059);\nc+=texture2D(image,p).rgb;} gl_FragColor=vec4(c/24.0,1.0);}\n', 'fragment': '#version 120\nvarying vec2 uv;\nvoid main(){vec2 p=(uv-0.5)*3.0;float a=0.0;\nfor(int i=0;i<40;i++){p=vec2(sin(p.x*1.71+p.y),cos(p.y*1.37-p.x))+uv;\na+=sin(p.x*p.y+float(i)*0.13);}\ngl_FragColor=vec4(0.5+0.5*cos(vec3(a,a+2.1,a+4.2)),1.0);}\n'}

class Gl:

    def __init__(self, mode):
        if os.name != 'nt' or mode not in mod:
            raise GlErr('Windows and a known workload required')
        self.hwnd = self.dc = self.rc = None
        self.mode = mode
        self.user = C.WinDLL('user32', use_last_error=True)
        self.gdi = C.WinDLL('gdi32', use_last_error=True)
        self.dll = C.WinDLL('opengl32', winmode=2048)
        self.user.CreateWindowExW.argtypes = [C.c_uint, C.c_wchar_p, C.c_wchar_p, C.c_uint, C.c_int, C.c_int, C.c_int, C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p]
        self.user.CreateWindowExW.restype = C.c_void_p
        self.user.GetDC.argtypes = [C.c_void_p]
        self.user.GetDC.restype = C.c_void_p
        self.user.ReleaseDC.argtypes = [C.c_void_p, C.c_void_p]
        self.user.DestroyWindow.argtypes = [C.c_void_p]
        self.gdi.ChoosePixelFormat.argtypes = [C.c_void_p, C.POINTER(Pfd)]
        self.gdi.ChoosePixelFormat.restype = C.c_int
        self.gdi.SetPixelFormat.argtypes = [C.c_void_p, C.c_int, C.POINTER(Pfd)]
        self.dll.wglCreateContext.argtypes = [C.c_void_p]
        self.dll.wglCreateContext.restype = C.c_void_p
        self.dll.wglMakeCurrent.argtypes = [C.c_void_p, C.c_void_p]
        self.dll.wglMakeCurrent.restype = C.c_int
        self.dll.wglDeleteContext.argtypes = [C.c_void_p]
        self.dll.wglGetProcAddress.argtypes = [C.c_char_p]
        self.dll.wglGetProcAddress.restype = C.c_void_p
        try:
            self.hwnd = self.user.CreateWindowExW(0, 'STATIC', 'Bounded offscreen GPU test', 0, 0, 0, 32, 32, None, None, None, None)
            if not self.hwnd:
                raise GlErr('Hidden context window creation failed')
            self.dc = self.user.GetDC(self.hwnd)
            p = Pfd()
            p.size = 40
            p.version = 1
            p.flags = 37
            p.color_bits = 32
            p.alpha_bits = 8
            fmt = self.gdi.ChoosePixelFormat(self.dc, C.byref(p))
            if not fmt or not self.gdi.SetPixelFormat(self.dc, fmt, C.byref(p)):
                raise GlErr('Pixel format unavailable')
            self.rc = self.dll.wglCreateContext(self.dc)
            if not self.rc or not self.dll.wglMakeCurrent(self.dc, self.rc):
                raise GlErr('Hardware GL context unavailable')
            self.setup()
        except BaseException:
            self.close()
            raise

    def fn(self, name, ret, *args):
        try:
            f = getattr(self.dll, name)
            f.restype = ret
            f.argtypes = list(args)
        except AttributeError:
            p = self.dll.wglGetProcAddress(name.encode('ascii'))
            if p in (None, 0, 1, 2, 3, C.c_void_p(-1).value):
                raise GlErr('Missing GL function ' + name)
            f = C.WINFUNCTYPE(ret, *args)(p)
        setattr(self, name, f)
        return f

    def setup(self):
        U, I, F, P = (C.c_uint, C.c_int, C.c_float, C.c_void_p)
        self.fn('glGetString', C.c_char_p, U)
        self.identity = {k: self.glGetString(n).decode('ascii', 'replace') for k, n in [('vendor', 7936), ('renderer', 7937), ('version', 7938)]}
        if 'NVIDIA' not in self.identity['vendor'] or 'GTX 950' not in self.identity['renderer']:
            raise GlErr('Unexpected rendering adapter ' + str(self.identity))
        spe = {'glGetError': (U,), 'glDisable': (None, U), 'glViewport': (None, I, I, I, I), 'glClearColor': (None, F, F, F, F), 'glClear': (None, U), 'glFinish': (None,), 'glReadPixels': (None, I, I, I, I, U, U, P), 'glGenTextures': (None, I, P), 'glBindTexture': (None, U, U), 'glTexParameteri': (None, U, U, I), 'glTexImage2D': (None, U, I, I, I, I, I, U, U, P), 'glGenFramebuffers': (None, I, P), 'glBindFramebuffer': (None, U, U), 'glFramebufferTexture2D': (None, U, U, U, U, I), 'glCheckFramebufferStatus': (U, U), 'glCreateShader': (U, U), 'glShaderSource': (None, U, I, P, P), 'glCompileShader': (None, U), 'glGetShaderiv': (None, U, U, P), 'glGetShaderInfoLog': (None, U, I, P, P), 'glCreateProgram': (U,), 'glAttachShader': (None, U, U), 'glBindAttribLocation': (None, U, U, C.c_char_p), 'glLinkProgram': (None, U), 'glGetProgramiv': (None, U, U, P), 'glGetProgramInfoLog': (None, U, I, P, P), 'glUseProgram': (None, U), 'glGenBuffers': (None, I, P), 'glBindBuffer': (None, U, U), 'glBufferData': (None, U, C.c_ssize_t, P, U), 'glEnableVertexAttribArray': (None, U), 'glVertexAttribPointer': (None, U, I, U, C.c_ubyte, I, P), 'glDrawArrays': (None, U, I, I), 'glGetUniformLocation': (I, U, C.c_char_p), 'glUniform1i': (None, I, I), 'glActiveTexture': (None, U)}
        for name, args in spe.items():
            self.fn(name, *args)
        self.glDisable(3024)
        self.glDisable(3042)
        self.glDisable(2929)
        self.color_tex = C.c_uint()
        self.glGenTextures(1, C.byref(self.color_tex))
        self.glBindTexture(3553, self.color_tex.value)
        self.glTexParameteri(3553, 10241, 9728)
        self.glTexParameteri(3553, 10240, 9728)
        self.glTexImage2D(3553, 0, 32856, wid, hei, 0, 6408, 5121, None)
        self.fbo = C.c_uint()
        self.glGenFramebuffers(1, C.byref(self.fbo))
        self.glBindFramebuffer(36160, self.fbo.value)
        self.glFramebufferTexture2D(36160, 36064, 3553, self.color_tex.value, 0)
        if self.glCheckFramebufferStatus(36160) != 36053:
            raise GlErr('Offscreen framebuffer incomplete')
        self.glViewport(0, 0, wid, hei)
        sha2 = []
        for kind, src2 in [(35633, ver3), (35632, fra[self.mode])]:
            sha = self.glCreateShader(kind)
            src = C.c_char_p(src2.encode())
            self.glShaderSource(sha, 1, C.byref(src), None)
            self.glCompileShader(sha)
            ok = C.c_int()
            self.glGetShaderiv(sha, 35713, C.byref(ok))
            if not ok.value:
                log = C.create_string_buffer(4096)
                self.glGetShaderInfoLog(sha, 4096, None, log)
                raise GlErr(log.value.decode())
            sha2.append(sha)
        self.program = self.glCreateProgram()
        for sha in sha2:
            self.glAttachShader(self.program, sha)
        self.glBindAttribLocation(self.program, 0, b'position')
        self.glBindAttribLocation(self.program, 1, b'color')
        self.glLinkProgram(self.program)
        ok = C.c_int()
        self.glGetProgramiv(self.program, 35714, C.byref(ok))
        if not ok.value:
            log = C.create_string_buffer(4096)
            self.glGetProgramInfoLog(self.program, 4096, None, log)
            raise GlErr(log.value.decode())
        self.glUseProgram(self.program)
        ver7 = []
        if self.mode == 'geometry':
            for y in range(128):
                for x in range(256):
                    x0 = x / 128 - 1
                    y0 = y / 64 - 1
                    x1 = (x + 1) / 128 - 1
                    y1 = (y + 1) / 64 - 1
                    col = (x / 255, y / 127, (x * 17 + y * 13) % 256 / 255)
                    for px, py in [(x0, y0), (x1, y0), (x0, y1), (x1, y0), (x1, y1), (x0, y1)]:
                        ver7.extend((px, py, *col))
        else:
            for x, y in [(-1, -1), (1, -1), (-1, 1), (1, -1), (1, 1), (-1, 1)]:
                ver7.extend((x, y, 1, 1, 1))
        self.count = len(ver7) // 5
        arr = (F * len(ver7))(*ver7)
        self.vbo = U()
        self.glGenBuffers(1, C.byref(self.vbo))
        self.glBindBuffer(34962, self.vbo.value)
        self.glBufferData(34962, C.sizeof(arr), arr, 35044)
        self.glEnableVertexAttribArray(0)
        self.glVertexAttribPointer(0, 2, 5126, 0, 20, None)
        self.glEnableVertexAttribArray(1)
        self.glVertexAttribPointer(1, 3, 5126, 0, 20, C.c_void_p(8))
        self.glBindTexture(3553, 0)
        if self.mode == 'texture':
            self.source_tex = U()
            self.glGenTextures(1, C.byref(self.source_tex))
            self.glActiveTexture(33984)
            self.glBindTexture(3553, self.source_tex.value)
            data = bytes((v for y in range(256) for x in range(256) for v in (x, y, 255 if (x // 16 + y // 16) % 2 else 0, 255)))
            pix = (C.c_ubyte * len(data)).from_buffer_copy(data)
            for par, val in [(10241, 9729), (10240, 9729), (10242, 10497), (10243, 10497)]:
                self.glTexParameteri(3553, par, val)
            self.glTexImage2D(3553, 0, 32856, 256, 256, 0, 6408, 5121, pix)
            self.glUniform1i(self.glGetUniformLocation(self.program, b'image'), 0)
        self.pixels = (C.c_ubyte * (wid * hei * 4))()
        self.error_check()

    def error_check(self):
        err2 = self.glGetError()
        if err2:
            raise GlErr(f'OpenGL error {err2:#x}')

    def draw(self):
        self.glClearColor(0.02, 0.03, 0.04, 1)
        self.glClear(16384)
        for _ in range(4 if self.mode == 'geometry' else 1):
            self.glDrawArrays(4, 0, self.count)
        self.glFinish()
        self.error_check()

    def pixels_bytes(self):
        self.glReadPixels(0, 0, wid, hei, 6408, 5121, self.pixels)
        self.error_check()
        return bytes(self.pixels)

    def close(self):
        if self.rc:
            self.dll.wglMakeCurrent(None, None)
            self.dll.wglDeleteContext(self.rc)
            self.rc = None
        if self.dc:
            self.user.ReleaseDC(self.hwnd, self.dc)
            self.dc = None
        if self.hwnd:
            self.user.DestroyWindow(self.hwnd)
            self.hwnd = None

def run(mode, args):
    out = args.directory.resolve()
    out.mkdir(parents=True, exist_ok=False)
    gl = None
    fra2 = che = 0
    max_fra = 0.0
    sta3 = None
    sts2 = 'failed'
    err2 = None
    try:
        if not 0 < args.seconds <= 100:
            raise GlErr('Duration must be within (0,100] seconds')
        gl = Gl(mode)
        gl.draw()
        ima = gl.pixels_bytes()
        dig = has2.sha256(ima).hexdigest()
        if len(set(ima[::4])) < 8:
            raise GlErr('Reference frame is blank or degenerate')
        if args.reference:
            ref = rd_json(args.reference)
            if any((ref[k] != v for k, v in [('mode', mode), ('width', wid), ('height', hei), ('fps_cap', FPS), ('identity', gl.identity), ('frame_sha256', dig)])):
                raise GlErr('Stock reference image or adapter differs')
        save_png(out / 'reference.png', ima)
        rea2 = {'pid': os.getpid(), 'mode': mode, 'width': wid, 'height': hei, 'fps_cap': FPS, 'identity': gl.identity, 'frame_sha256': dig, 'vertices_per_draw': gl.count, 'draws_per_frame': 4 if mode == 'geometry' else 1, 'status': 'ready', 'monotonic': time.monotonic()}
        ato(out / 'ready.json', rea2)
        wait_dea = time.monotonic() + 360
        while args.start_file and (not args.start_file.exists()):
            if args.stop_file and args.stop_file.exists():
                raise GlErr('Stopped before scheduling')
            if time.monotonic() > wait_dea:
                raise GlErr('No schedule arrived')
            time.sleep(0.05)
        if args.start_file:
            sch = rd_json(args.start_file)
            sta2 = sch['start_monotonic'] + args.phase * 100
        else:
            sta2 = time.monotonic()
        end = sta2 + args.seconds
        while time.monotonic() < sta2:
            if args.stop_file and args.stop_file.exists():
                raise GlErr('Stopped while armed')
            time.sleep(min(0.05, max(0, sta2 - time.monotonic())))
        sta3 = time.monotonic()
        next_chk = sta3
        next_fra = sta3
        while time.monotonic() < end:
            if args.stop_file and args.stop_file.exists():
                sts2 = 'stopped'
                break
            tick = time.monotonic()
            gl.draw()
            max_fra = max(max_fra, time.monotonic() - tick)
            fra2 += 1
            now = time.monotonic()
            if now >= next_chk:
                act = has2.sha256(gl.pixels_bytes()).hexdigest()
                che += 1
                if act != dig:
                    raise GlErr('Rendered frame differs from verified stock reference')
                ato(out / 'heartbeat.json', {'pid': os.getpid(), 'mode': mode, 'monotonic': time.monotonic(), 'frames': fra2, 'checks': che, 'frame_sha256': act, 'max_draw_seconds': max_fra, 'elapsed_seconds': now - sta3, 'status': 'running'})
                next_chk = now + 1
            next_fra = max(next_fra + 1 / FPS, time.monotonic())
            time.sleep(min(max(0, next_fra - time.monotonic()), max(0, end - time.monotonic())))
        else:
            sts2 = 'completed'
    except BaseException as exc:
        err2 = str(exc)
        sts2 = 'failed'
    finally:
        dt = time.monotonic() - sta3 if sta3 is not None else 0
        if gl:
            gl.close()
        res4 = {'mode': mode, 'pid': os.getpid(), 'status': sts2, 'error': err2, 'frames': fra2, 'checksum_checks': che, 'elapsed_seconds': dt, 'fps': fra2 / dt if dt else None, 'max_draw_seconds': max_fra, 'clock_or_voltage_setters_used': False, 'finished_monotonic': time.monotonic()}
        ato(out / 'result.json', res4)
        print(json.dumps(res4), flush=True)
    return 0 if sts2 == 'completed' else 2

def main(mode):
    p = arg.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--seconds', type=float, default=2)
    p.add_argument('--reference', type=Path)
    p.add_argument('--start-file', type=Path)
    p.add_argument('--stop-file', type=Path)
    p.add_argument('--phase', type=int, choices=range(3), default=0)
    return run(mode, p.parse_args())
