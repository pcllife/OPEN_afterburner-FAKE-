// _abi_
use std::fmt;
pub const SIG: u32 = 0x4d41_434d;
pub const VER: u32 = 0x0002_0003;
pub const HDR_SZ: usize = 36;
pub const ENT_SZ: usize = 3760;
pub const MAX_BUF: usize = 64 * 1024 * 1024;
const CV_OFF: usize = 276;
const GPU_ID_OFF: usize = 3500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hdr {
    pub ver: u32,
    pub hdr_sz: usize,
    pub gpu_cnt: usize,
    pub gpu_ent_sz: usize,
    pub mst_gpu: u32,
    pub flags: u32,
    pub set_tm: i32,
    pub cmd: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rng {
    pub name: &'static str,
    pub unt: &'static str,
    pub cur: i64,
    pub min: i64,
    pub max: i64,
    pub dft: i64,
}
impl Rng {
    pub fn ord(&self) -> bool {
        self.min <= self.max
    }
    pub fn cur_in_rng(&self) -> bool {
        self.ord() && (self.min..=self.max).contains(&self.cur)
    }
    pub fn dft_in_rng(&self) -> bool {
        self.ord() && (self.min..=self.max).contains(&self.dft)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cv {
    pub en: bool,
    pub pts: u32,
    pub lock_idx1: u32,
    pub pwr_tp: u32,
    pub thm_tp: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpu {
    pub id: String,
    pub flags: u32,
    pub rngs: Vec<Rng>,
    pub cv: Option<Cv>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snap {
    pub hdr: Hdr,
    pub gpus: Vec<Gpu>,
}

#[derive(Clone, Copy)]
struct Fld {
    name: &'static str,
    unt: &'static str,
    off: usize,
    flag: u32,
    sgn: bool,
    min_dlt: usize,
}
const FLDS: [Fld; 16] = [
    Fld {
        name: "core_clock",
        unt: "kHz",
        off: 4,
        flag: 1,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "shader_clock",
        unt: "kHz",
        off: 20,
        flag: 2,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "memory_clock",
        unt: "kHz",
        off: 36,
        flag: 4,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "fan_speed",
        unt: "%",
        off: 52,
        flag: 8,
        sgn: false,
        min_dlt: 8,
    },
    Fld {
        name: "core_voltage",
        unt: "mV",
        off: 76,
        flag: 0x10,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "memory_voltage",
        unt: "mV",
        off: 92,
        flag: 0x20,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "aux_voltage",
        unt: "mV",
        off: 108,
        flag: 0x40,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "core_voltage_offset",
        unt: "mV",
        off: 124,
        flag: 0x80,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "memory_voltage_offset",
        unt: "mV",
        off: 140,
        flag: 0x100,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "aux_voltage_offset",
        unt: "mV",
        off: 156,
        flag: 0x200,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "power_limit",
        unt: "%",
        off: 172,
        flag: 0x400,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "core_clock_offset",
        unt: "kHz",
        off: 188,
        flag: 0x800,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "memory_clock_offset",
        unt: "kHz",
        off: 204,
        flag: 0x1000,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "thermal_limit",
        unt: "C",
        off: 220,
        flag: 0x2000,
        sgn: true,
        min_dlt: 4,
    },
    Fld {
        name: "aux2_voltage",
        unt: "mV",
        off: 244,
        flag: 0x8000,
        sgn: false,
        min_dlt: 4,
    },
    Fld {
        name: "aux2_voltage_offset",
        unt: "mV",
        off: 260,
        flag: 0x10000,
        sgn: true,
        min_dlt: 4,
    },
];
fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(
        buf[off..off + 4]
            .try_into()
            .expect("validated layout bounds"),
    )
}
impl Hdr {
    pub fn prs(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < HDR_SZ {
            return Err(Error("truncated MACM header".into()));
        }
        if u32_at(buf, 0) != SIG {
            return Err(Error("MACM is uninitialized or deallocating".into()));
        }
        let h = Self {
            ver: u32_at(buf, 4),
            hdr_sz: u32_at(buf, 8) as usize,
            gpu_cnt: u32_at(buf, 12) as usize,
            gpu_ent_sz: u32_at(buf, 16) as usize,
            mst_gpu: u32_at(buf, 20),
            flags: u32_at(buf, 24),
            set_tm: u32_at(buf, 28) as i32,
            cmd: u32_at(buf, 32),
        };
        if h.ver != VER {
            return Err(Error(format!(
                "unsupported MACM version {:#x}; only the verified 2.3 layout is accepted",
                h.ver
            )));
        }
        if h.hdr_sz < HDR_SZ || h.gpu_cnt > 0 && h.gpu_ent_sz < ENT_SZ {
            return Err(Error(
                "MACM declared stride is smaller than verified v2.3 layout".into(),
            ));
        }
        if h.gpu_cnt > 0 && h.mst_gpu as usize >= h.gpu_cnt {
            return Err(Error("MACM master GPU is out of range".into()));
        }
        h.req_len()?;
        Ok(h)
    }
    pub fn req_len(&self) -> Result<usize, Error> {
        let tot = self
            .gpu_cnt
            .checked_mul(self.gpu_ent_sz)
            .and_then(|n| self.hdr_sz.checked_add(n))
            .ok_or_else(|| Error("MACM size overflow".into()))?;
        if tot > MAX_BUF {
            return Err(Error("MACM snapshot exceeds allocation limit".into()));
        }
        Ok(tot)
    }
}
pub fn prs(buf: &[u8]) -> Result<Snap, Error> {
    let hdr = Hdr::prs(buf)?;
    if buf.len() < hdr.req_len()? {
        return Err(Error("truncated MACM GPU array".into()));
    }
    let mut gpus = Vec::with_capacity(hdr.gpu_cnt);
    for idx in 0..hdr.gpu_cnt {
        let beg = hdr.hdr_sz + idx * hdr.gpu_ent_sz;
        let rec = &buf[beg..beg + ENT_SZ];
        let flags = u32_at(rec, 0);
        let mut rngs = Vec::new();
        for fld in FLDS {
            if flags & fld.flag == 0 {
                continue;
            }
            let val = |dlt| {
                let raw = u32_at(rec, fld.off + dlt);
                if fld.sgn {
                    raw as i32 as i64
                } else {
                    raw as i64
                }
            };
            rngs.push(Rng {
                name: fld.name,
                unt: fld.unt,
                cur: val(0),
                min: val(fld.min_dlt),
                max: val(fld.min_dlt + 4),
                dft: val(fld.min_dlt + 8),
            });
        }
        let cv = if flags & 0x20000 != 0 {
            let c = &rec[CV_OFF..GPU_ID_OFF];
            let pts = u32_at(c, 8);
            let lock = u32_at(c, 3084);
            let power = u32_at(c, 3088);
            let thermal = u32_at(c, 3156);
            if pts > 256 || power > 4 || thermal > 4 || lock > pts {
                return Err(Error(format!("invalid curve count/lock for GPU {idx}")));
            }
            Some(Cv {
                en: flags & 0x40000 != 0,
                pts,
                lock_idx1: lock,
                pwr_tp: power,
                thm_tp: thermal,
            })
        } else {
            None
        };
        let raw = &rec[GPU_ID_OFF..GPU_ID_OFF + 260];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        gpus.push(Gpu {
            id: String::from_utf8_lossy(&raw[..end]).into_owned(),
            flags,
            rngs,
            cv,
        });
    }
    Ok(Snap { hdr, gpus })
}
#[cfg(test)]
// _test_
mod tests {
    use super::*;
    fn set(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn fx() -> Vec<u8> {
        let mut b = vec![0; HDR_SZ + ENT_SZ];
        for (off, v) in [(0, SIG), (4, VER), (8, 36), (12, 1), (16, 3760), (20, 0)] {
            set(&mut b, off, v);
        }
        set(&mut b, HDR_SZ, 0x800);
        set(&mut b, HDR_SZ + 188, (-12500i32) as u32);
        set(&mut b, HDR_SZ + 192, (-90000i32) as u32);
        set(&mut b, HDR_SZ + 196, 135000);
        b[HDR_SZ + GPU_ID_OFF..HDR_SZ + GPU_ID_OFF + 7].copy_from_slice(b"GPU_ID0");
        b
    }
    #[test]
    fn t_sig_off_and_id() {
        let b = fx();
        let p = prs(&b).unwrap();
        assert_eq!(&b[..4], b"MCAM");
        assert_eq!(p.gpus[0].id, "GPU_ID0");
        let r = &p.gpus[0].rngs[0];
        assert_eq!((r.cur, r.min, r.max, r.dft), (-12500, -90000, 135000, 0));
        assert!(r.cur_in_rng());
    }
    #[test]
    fn t_uns_fie_are_not_rep_as_zer() {
        let p = prs(&fx()).unwrap();
        assert_eq!(p.gpus[0].rngs.len(), 1);
        assert!(p.gpus[0].cv.is_none());
    }
    #[test]
    fn t_fan_fla_do_not_shi_min_and_max() {
        let mut b = fx();
        set(&mut b, 36, 8);
        for (off, v) in [(52, 40), (56, 1), (60, 30), (64, 100), (68, 35)] {
            set(&mut b, 36 + off, v);
        }
        let p = prs(&b).unwrap();
        let r = &p.gpus[0].rngs[0];
        assert_eq!((r.cur, r.min, r.max, r.dft), (40, 30, 100, 35));
    }
    #[test]
    fn t_unk_ver_and_sig_rej() {
        for (off, v) in [
            (0, 0xdead),
            (0, 0x4d43414d),
            (4, 0x20002),
            (4, 0x20004),
            (4, 0x30000),
        ] {
            let mut b = fx();
            set(&mut b, off, v);
            assert!(prs(&b).is_err());
        }
    }
    #[test]
    fn t_bou_che_bef_all() {
        for (off, v) in [(8, 35), (16, 3759), (12, u32::MAX), (20, 1)] {
            let mut b = fx();
            set(&mut b, off, v);
            assert!(prs(&b).is_err());
        }
    }
    #[test]
    fn t_tru_rej() {
        let b = fx();
        assert!(prs(&b[..35]).is_err());
        assert!(prs(&b[..b.len() - 1]).is_err());
    }
    #[test]
    fn t_dec_ext_str_are_hon() {
        let mut b = fx();
        b.splice(36..36, [0u8; 8]);
        set(&mut b, 8, 44);
        b.extend([0u8; 16]);
        set(&mut b, 16, 3776);
        assert_eq!(prs(&b).unwrap().gpus[0].id, "GPU_ID0");
    }
    #[test]
    fn t_ran_do_not_cla_sta() {
        let mut b = fx();
        set(&mut b, 36 + 192, 200000);
        let p = prs(&b).unwrap();
        let r = &p.gpus[0].rngs[0];
        assert!(!r.ord());
        assert!(!r.cur_in_rng());
        assert!(!r.dft_in_rng());
    }
    #[test]
    fn t_cur_cou_and_loc_are_bou() {
        for (off, v) in [(8, 257), (3084, 1), (3088, 5), (3156, 5)] {
            let mut b = fx();
            set(&mut b, 36, 0x20000);
            set(&mut b, 36 + 276 + off, v);
            assert!(prs(&b).is_err());
        }
    }
    #[test]
    fn t_val_cur_sum() {
        let mut b = fx();
        set(&mut b, 36, 0x60000);
        set(&mut b, 36 + 276 + 8, 2);
        set(&mut b, 36 + 276 + 3084, 2);
        let p = prs(&b).unwrap();
        let c = p.gpus[0].cv.as_ref().unwrap();
        assert!(c.en);
        assert_eq!(c.pts, 2);
        assert_eq!(c.lock_idx1, 2);
    }
    #[test]
    fn t_emp_ini_sna() {
        let mut b = fx();
        set(&mut b, 12, 0);
        set(&mut b, 16, 0);
        b.truncate(36);
        assert!(prs(&b).unwrap().gpus.is_empty());
    }
}
