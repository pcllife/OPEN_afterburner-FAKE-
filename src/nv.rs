// _abi_
use std::mem::size_of;

#[cfg(windows)]
#[path = "ni.rs"]
mod ids;

#[derive(Debug, Clone)]
pub struct Temp {
    pub tgt: i32,
    pub cel: i32,
}
#[derive(Debug, Clone)]
pub struct Gpu {
    pub name: String,
    pub use_pct: [Option<u32>; 4],
    pub gfx_mhz: Option<f64>,
    pub mem_mhz: Option<f64>,
    pub temps: Vec<Temp>,
    pub fan_rpm: Option<u32>,
    pub ded_kib: Option<u32>,
    pub avail_kib: Option<u32>,
    pub warns: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct Snap {
    pub drv_ver: Option<u32>,
    pub drv_br: Option<String>,
    pub gpus: Vec<Gpu>,
    pub warns: Vec<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
mod abi {
    use super::size_of;
    #[derive(Default, Copy, Clone)]
    #[repr(C)]
    pub struct Dom {
        pub pres: u32,
        pub val: u32,
    }
    #[derive(Default)]
    #[repr(C)]
    pub struct DynPs {
        pub ver: u32,
        pub flags: u32,
        pub util: [Dom; 8],
    }
    #[derive(Default)]
    #[repr(C)]
    pub struct Clk {
        pub ver: u32,
        pub clk_ty: u32,
        pub doms: [Dom; 32],
    }
    #[derive(Default, Copy, Clone)]
    #[repr(C)]
    pub struct Tsn {
        pub ctrl: i32,
        pub dft_min: i32,
        pub dft_max: i32,
        pub cur: i32,
        pub tgt: i32,
    }
    #[derive(Default)]
    #[repr(C)]
    pub struct Thm {
        pub ver: u32,
        pub cnt: u32,
        pub sens: [Tsn; 3],
    }
    #[derive(Default)]
    #[repr(C)]
    pub struct Mem2 {
        pub ver: u32,
        pub ded: u32,
        pub alloc_avail: u32,
        pub system: u32,
        pub shared: u32,
        pub cur_avail: u32,
    }
    pub const fn ver<T>(rev: u32) -> u32 {
        (size_of::<T>() as u32) | (rev << 16)
    }
    pub fn pct(dom: &Dom) -> Option<u32> {
        (dom.pres & 1 != 0 && dom.val <= 100).then_some(dom.val)
    }
    pub fn mhz(dom: &Dom) -> Option<f64> {
        (dom.pres & 1 != 0).then_some(dom.val as f64 / 1000.0)
    }
}

#[cfg(windows)]
mod plat {
    use super::{Gpu, Snap, Temp, abi::*, ids};
    use std::{ffi::c_void, ptr};

    type Hnd = *mut c_void;

    type Qry = unsafe extern "C" fn(u32) -> *mut c_void;
    type Lfc = unsafe extern "C" fn() -> i32;
    type EnmGpu = unsafe extern "C" fn(*mut Hnd, *mut u32) -> i32;
    type GpuNm = unsafe extern "C" fn(Hnd, *mut u8) -> i32;
    type Dyn = unsafe extern "C" fn(Hnd, *mut DynPs) -> i32;
    type GetClk = unsafe extern "C" fn(Hnd, *mut Clk) -> i32;
    type GetThm = unsafe extern "C" fn(Hnd, u32, *mut Thm) -> i32;
    type Tach = unsafe extern "C" fn(Hnd, *mut u32) -> i32;
    type Mem = unsafe extern "C" fn(Hnd, *mut Mem2) -> i32;
    type Drv = unsafe extern "C" fn(*mut u32, *mut u8) -> i32;
    const OK: i32 = 0;
    const ERR_VER: i32 = -9;
    const GPU_MAX: usize = 64;
    const STR_SZ: usize = 64;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: Hnd, flags: u32) -> Hnd;
        fn GetProcAddress(mdl: Hnd, name: *const u8) -> *mut c_void;
        fn FreeLibrary(mdl: Hnd) -> i32;
    }
    struct Lib(Hnd);
    impl Drop for Lib {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }
    struct Api {
        _lib: Lib,
        qry: Qry,
        unld: Lfc,
    }
    impl Drop for Api {
        fn drop(&mut self) {
            unsafe {
                (self.unld)();
            }
        }
    }
    impl Api {
        // _guard_
        fn open() -> Result<Self, String> {
            let name = if cfg!(target_pointer_width = "64") {
                "nvapi64.dll"
            } else {
                "nvapi.dll"
            };
            let wstr: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();

            let mdl = unsafe {
                LoadLibraryExW(wstr.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)
            };
            if mdl.is_null() {
                return Err(format!(
                    "Cannot load system {name}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let lib = Lib(mdl);
            let addr = unsafe { GetProcAddress(lib.0, c"nvapi_QueryInterface".as_ptr().cast()) };
            if addr.is_null() {
                return Err("System NVAPI has no nvapi_QueryInterface export".into());
            }

            let qry: Qry = unsafe { std::mem::transmute(addr) };
            let init = unsafe { qry(ids::INIT) };
            let unld = unsafe { qry(ids::UNLD) };
            if init.is_null() || unld.is_null() {
                return Err("NVAPI lifecycle interface is unavailable".into());
            }
            let init: Lfc = unsafe { std::mem::transmute(init) };
            let unld: Lfc = unsafe { std::mem::transmute(unld) };
            let sts = unsafe { init() };
            if sts != OK {
                return Err(format!("NvAPI_Initialize failed with status {sts}"));
            }
            Ok(Self {
                _lib: lib,
                qry,
                unld,
            })
        }
        fn addr(&self, id: u32) -> Option<*mut c_void> {
            let addr = unsafe { (self.qry)(id) };
            (!addr.is_null()).then_some(addr)
        }
    }

    macro_rules! func {
        ($api:expr, $id:expr, $ty:ty) => {
            $api.addr($id)
                .map(|addr| unsafe { std::mem::transmute::<*mut c_void, $ty>(addr) })
        };
    }
    fn short_str(val: &[u8; STR_SZ]) -> String {
        let end = val.iter().position(|&b| b == 0).unwrap_or(val.len());
        String::from_utf8_lossy(&val[..end]).into_owned()
    }
    fn read<T>(
        func: Option<T>,
        lbl: &str,
        warns: &mut Vec<String>,
        qry: impl FnOnce(T) -> i32,
    ) -> bool {
        let Some(func) = func else {
            warns.push(format!("{lbl}: interface unavailable"));
            return false;
        };
        let sts = qry(func);
        if sts == OK {
            true
        } else {
            warns.push(format!("{lbl}: NVAPI status {sts}"));
            false
        }
    }
    pub fn snap() -> Result<Snap, String> {
        let api = Api::open()?;
        let enumerate = func!(api, ids::ENUM_GPU, EnmGpu)
            .ok_or("NvAPI_EnumPhysicalGPUs interface unavailable")?;
        let mut hnds = [ptr::null_mut(); GPU_MAX];
        let mut cnt = 0;
        let sts = unsafe { enumerate(hnds.as_mut_ptr(), &mut cnt) };
        if sts != OK {
            return Err(format!("NvAPI_EnumPhysicalGPUs failed with status {sts}"));
        }
        if cnt as usize > GPU_MAX {
            return Err("NVAPI returned an out-of-bounds GPU count".into());
        }
        let full_nm = func!(api, ids::GET_NM, GpuNm);
        let dyn_ps = func!(api, ids::GET_DYN, Dyn);
        let clks = func!(api, ids::GET_CLK, GetClk);
        let thms = func!(api, ids::GET_THM, GetThm);
        let tach = func!(api, ids::GET_TACH, Tach);
        let mem = func!(api, ids::GET_MEM, Mem);
        let drv = func!(api, ids::GET_DRV, Drv);
        let mut res = Snap {
            drv_ver: None,
            drv_br: None,
            gpus: Vec::new(),
            warns: Vec::new(),
        };
        let mut drv_ver = 0;
        let mut br = [0u8; STR_SZ];
        if read(drv, "driver version", &mut res.warns, |func| unsafe {
            func(&mut drv_ver, br.as_mut_ptr())
        }) {
            res.drv_ver = Some(drv_ver);
            res.drv_br = Some(short_str(&br));
        }
        for (idx, &hnd) in hnds[..cnt as usize].iter().enumerate() {
            if hnd.is_null() {
                return Err(format!(
                    "NVAPI returned a null physical GPU handle at {idx}"
                ));
            }
            let mut gpu = Gpu {
                name: format!("NVIDIA GPU {idx}"),
                use_pct: [None; 4],
                gfx_mhz: None,
                mem_mhz: None,
                temps: Vec::new(),
                fan_rpm: None,
                ded_kib: None,
                avail_kib: None,
                warns: Vec::new(),
            };
            let mut name = [0u8; STR_SZ];
            if read(full_nm, "GPU name", &mut gpu.warns, |func| unsafe {
                func(hnd, name.as_mut_ptr())
            }) {
                gpu.name = short_str(&name);
            }
            let mut usage = DynPs {
                ver: ver::<DynPs>(1),
                ..Default::default()
            };
            if read(dyn_ps, "utilization", &mut gpu.warns, |func| unsafe {
                func(hnd, &mut usage)
            }) {
                for (dest, src) in gpu.use_pct.iter_mut().zip(&usage.util) {
                    *dest = pct(src);
                }
            }
            let mut freqs = Clk {
                ver: ver::<Clk>(3),
                ..Default::default()
            };
            if read(clks, "current clocks", &mut gpu.warns, |func| {
                let mut sts = unsafe { func(hnd, &mut freqs) };

                // _abi_
                for rev in [2, 1] {
                    if sts != ERR_VER {
                        break;
                    }
                    freqs = Clk {
                        ver: ver::<Clk>(rev),
                        ..Default::default()
                    };
                    sts = unsafe { func(hnd, &mut freqs) };
                }
                sts
            }) {
                gpu.gfx_mhz = mhz(&freqs.doms[0]);
                gpu.mem_mhz = mhz(&freqs.doms[4]);
            }
            let mut temp = Thm {
                ver: ver::<Thm>(2),
                ..Default::default()
            };
            if read(thms, "temperature", &mut gpu.warns, |func| unsafe {
                func(hnd, 15, &mut temp)
            }) {
                if temp.cnt as usize > temp.sens.len() {
                    gpu.warns
                        .push("temperature: invalid returned sensor count".into());
                } else {
                    gpu.temps = temp.sens[..temp.cnt as usize]
                        .iter()
                        .map(|sen| Temp {
                            tgt: sen.tgt,
                            cel: sen.cur,
                        })
                        .collect();
                }
            }
            let mut rpm = 0;
            if read(tach, "fan tachometer", &mut gpu.warns, |func| unsafe {
                func(hnd, &mut rpm)
            }) {
                gpu.fan_rpm = Some(rpm);
            }
            let mut info = Mem2 {
                ver: ver::<Mem2>(2),
                ..Default::default()
            };
            if read(mem, "dedicated memory", &mut gpu.warns, |func| unsafe {
                func(hnd, &mut info)
            }) {
                gpu.ded_kib = Some(info.ded);
                gpu.avail_kib = Some(info.cur_avail);
            }
            res.gpus.push(gpu);
        }
        Ok(res)
    }
}

#[cfg(windows)]
pub use plat::snap;
#[cfg(not(windows))]
pub fn snap() -> Result<Snap, String> {
    Err("NVAPI live monitoring is Windows-only".into())
}

#[cfg(test)]
// _test_
mod tests {
    use super::abi::*;
    use std::mem::{align_of, offset_of, size_of};
    #[test]
    fn t_dyn_str_mat_nvi_hea() {
        assert_eq!(size_of::<DynPs>(), 72);
        assert_eq!(ver::<DynPs>(1), 0x10048);
        assert_eq!(offset_of!(DynPs, util), 8);
        assert_eq!(size_of::<Dom>(), 8);
    }
    #[test]
    fn t_clo_str_mat_nvi_hea() {
        assert_eq!(size_of::<Clk>(), 264);
        assert_eq!(ver::<Clk>(3), 0x30108);
        assert_eq!(offset_of!(Clk, doms), 8);
        assert_eq!(align_of::<Clk>(), 4);
    }
    #[test]
    fn t_the_str_is_sig_v2() {
        assert_eq!(size_of::<Thm>(), 68);
        assert_eq!(ver::<Thm>(2), 0x20044);
        assert_eq!(size_of::<Tsn>(), 20);
        assert_eq!(offset_of!(Tsn, cur), 12);
    }
    #[test]
    fn t_mem_str_mat_v2() {
        assert_eq!(size_of::<Mem2>(), 24);
        assert_eq!(ver::<Mem2>(2), 0x20018);
        assert_eq!(offset_of!(Mem2, cur_avail), 20);
    }
    #[test]
    fn t_mis_and_inv_per_is_not_zer() {
        assert_eq!(pct(&Dom { pres: 0, val: 42 }), None);
        assert_eq!(
            pct(&Dom {
                pres: 1,
                val: u32::MAX
            }),
            None
        );
        assert_eq!(pct(&Dom { pres: 1, val: 101 }), None);
        assert_eq!(pct(&Dom { pres: 1, val: 0 }), Some(0));
        assert_eq!(pct(&Dom { pres: 1, val: 100 }), Some(100));
    }
    #[test]
    fn t_clo_pre_and_khz_to_mhz_con() {
        assert_eq!(
            mhz(&Dom {
                pres: 0,
                val: 135000
            }),
            None
        );
        assert_eq!(
            mhz(&Dom {
                pres: 1,
                val: 135000
            }),
            Some(135.0)
        );
        assert_eq!(mhz(&Dom { pres: 1, val: 0 }), Some(0.0));
    }
}
