// _abi_
use std::fmt;

pub const SIG: u32 = 0x4d41_484d;
pub const HDR_SZ: usize = 32;
pub const ENT_SZ: usize = 1324;
pub const GPU_ENT_SZ: usize = 1304;
pub const MAX_SNAP: usize = 64 * 1024 * 1024;
const TXT_SZ: usize = 260;

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
    pub ent_cnt: usize,
    pub ent_sz: usize,
    pub poll_tm: i32,
    pub gpu_cnt: usize,
    pub gpu_ent_sz: usize,
}

#[derive(Debug, Clone)]
pub struct Ent {
    pub name: String,
    pub unt: String,
    pub loc_nm: String,
    pub loc_u: String,
    pub rec_fmt: String,
    pub val: Option<f32>,
    pub min_lim: Option<f32>,
    pub max_lim: Option<f32>,
    pub flags: u32,

    pub inst: Option<u32>,
    pub src_id: u32,
}

#[derive(Debug, Clone)]
pub struct Gpu {
    pub id: String,
    pub fam: String,
    pub dev: String,
    pub drv: String,
    pub bios: String,
    pub mem_kb: u32,
}

#[derive(Debug, Clone)]
pub struct Snap {
    pub hdr: Hdr,
    pub ents: Vec<Ent>,
    pub gpus: Vec<Gpu>,
}

fn dword(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(
        buf[off..off + 4]
            .try_into()
            .expect("validated field bounds"),
    )
}
fn txt(buf: &[u8], off: usize) -> String {
    let fld = &buf[off..off + TXT_SZ];
    let end = fld.iter().position(|&b| b == 0).unwrap_or(fld.len());

    String::from_utf8_lossy(&fld[..end]).into_owned()
}
fn unt(buf: &[u8], off: usize) -> String {
    let fld = &buf[off..off + TXT_SZ];
    let end = fld.iter().position(|&b| b == 0).unwrap_or(fld.len());

    match &fld[..end] {
        b"\xb0C" => "\u{00b0}C".into(),
        b"\xb0F" => "\u{00b0}F".into(),
        _ => txt(buf, off),
    }
}
fn opt_f32(buf: &[u8], off: usize) -> Option<f32> {
    let val = f32::from_bits(dword(buf, off));
    (val.is_finite() && val != f32::MAX).then_some(val)
}

impl Hdr {
    pub fn prs(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < HDR_SZ {
            return Err(Error(format!(
                "truncated MAHM header: need {HDR_SZ}, got {}",
                buf.len()
            )));
        }
        let signature = dword(buf, 0);
        if signature != SIG {
            return Err(Error(format!(
                "MAHM is not initialized or is deallocating: signature {signature:#010x}"
            )));
        }
        let hdr = Self {
            ver: dword(buf, 4),
            hdr_sz: dword(buf, 8) as usize,
            ent_cnt: dword(buf, 12) as usize,
            ent_sz: dword(buf, 16) as usize,
            poll_tm: dword(buf, 20) as i32,
            gpu_cnt: dword(buf, 24) as usize,
            gpu_ent_sz: dword(buf, 28) as usize,
        };
        if hdr.ver >> 16 != 2 {
            return Err(Error(format!(
                "unsupported MAHM version {:#010x}; expected 2.x",
                hdr.ver
            )));
        }
        if hdr.hdr_sz < HDR_SZ {
            return Err(Error(
                "MAHM header size is smaller than the v2 layout".into(),
            ));
        }
        if hdr.ent_cnt > 0 && hdr.ent_sz < ENT_SZ {
            return Err(Error(
                "MAHM source stride is smaller than the v2 layout".into(),
            ));
        }
        if hdr.gpu_cnt > 0 && hdr.gpu_ent_sz < GPU_ENT_SZ {
            return Err(Error(
                "MAHM GPU stride is smaller than the v2 layout".into(),
            ));
        }
        hdr.req_len()?;
        Ok(hdr)
    }

    pub fn req_len(&self) -> Result<usize, Error> {
        let need = self
            .ent_cnt
            .checked_mul(self.ent_sz)
            .and_then(|n| self.hdr_sz.checked_add(n))
            .and_then(|n| {
                self.gpu_cnt
                    .checked_mul(self.gpu_ent_sz)
                    .and_then(|g| n.checked_add(g))
            })
            .ok_or_else(|| Error("MAHM layout size overflow".into()))?;
        if need > MAX_SNAP {
            return Err(Error(format!(
                "MAHM layout exceeds the {}-byte allocation limit",
                MAX_SNAP
            )));
        }
        Ok(need)
    }
}

pub fn is_gpu_src(id: u32) -> bool {
    matches!(id, 0x00..=0x03 | 0x10..=0x15 | 0x20..=0x22 | 0x30..=0x35 |
        0x40..=0x43 | 0x60..=0x61 | 0x70..=0x72 | 0x74..=0x75 |
        0xb0..=0xb3 | 0xc0..=0xc3 | 0xd0..=0xd3 | 0xf0)
}

impl Ent {
    pub fn scp(&self) -> &'static str {
        if self.inst.is_none() {
            "global"
        } else if is_gpu_src(self.src_id) {
            "gpu"
        } else if matches!(self.src_id, 0x50..=0x56 | 0x80 | 0x90..=0x93 | 0xa0 |
                         0xf1..=0xf7 | 0xff | 0x100)
        {
            "system"
        } else {
            "unknown"
        }
    }
}

pub fn prs(buf: &[u8]) -> Result<Snap, Error> {
    let hdr = Hdr::prs(buf)?;
    let need = hdr.req_len()?;
    if buf.len() < need {
        return Err(Error(format!(
            "truncated MAHM snapshot: need {need}, got {}",
            buf.len()
        )));
    }
    let mut ents = Vec::with_capacity(hdr.ent_cnt);
    for idx in 0..hdr.ent_cnt {
        let off = hdr.hdr_sz + idx * hdr.ent_sz;
        let rec = &buf[off..off + ENT_SZ];
        let raw_gpu = dword(rec, 1316);
        let inst = (raw_gpu != u32::MAX).then_some(raw_gpu);
        let src_id = dword(rec, 1320);
        if is_gpu_src(src_id) && inst.is_some_and(|id| id as usize >= hdr.gpu_cnt) {
            return Err(Error(format!(
                "GPU source {idx} references out-of-range GPU {raw_gpu}"
            )));
        }
        ents.push(Ent {
            name: txt(rec, 0),
            unt: unt(rec, 260),
            loc_nm: txt(rec, 520),
            loc_u: txt(rec, 780),
            rec_fmt: txt(rec, 1040),
            val: opt_f32(rec, 1300),
            min_lim: opt_f32(rec, 1304),
            max_lim: opt_f32(rec, 1308),
            flags: dword(rec, 1312),
            inst,
            src_id,
        });
    }
    let gpu_beg = hdr.hdr_sz + hdr.ent_cnt * hdr.ent_sz;
    let mut gpus = Vec::with_capacity(hdr.gpu_cnt);
    for idx in 0..hdr.gpu_cnt {
        let off = gpu_beg + idx * hdr.gpu_ent_sz;
        let rec = &buf[off..off + GPU_ENT_SZ];
        gpus.push(Gpu {
            id: txt(rec, 0),
            fam: txt(rec, 260),
            dev: txt(rec, 520),
            drv: txt(rec, 780),
            bios: txt(rec, 1040),
            mem_kb: dword(rec, 1300),
        });
    }
    Ok(Snap { hdr, ents, gpus })
}

#[cfg(test)]
// _test_
mod tests {
    use super::*;

    fn set(buf: &mut [u8], off: usize, val: u32) {
        buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
    }
    fn fx(hdr_sz: usize, strd: usize, gpu_str: usize) -> Vec<u8> {
        let mut buf = vec![0; hdr_sz + strd + gpu_str];
        for (off, val) in [
            (0, SIG),
            (4, 0x0002_0000),
            (8, hdr_sz as u32),
            (12, 1),
            (16, strd as u32),
            (20, 12345),
            (24, 1),
            (28, gpu_str as u32),
        ] {
            set(&mut buf, off, val);
        }
        buf[hdr_sz..hdr_sz + 9].copy_from_slice(b"GPU usage");
        buf[hdr_sz + 260] = b'%';
        buf[hdr_sz + 1040..hdr_sz + 1044].copy_from_slice(b"%.1f");
        set(&mut buf, hdr_sz + 1300, 42.5f32.to_bits());
        set(&mut buf, hdr_sz + 1308, 100.0f32.to_bits());
        set(&mut buf, hdr_sz + 1320, 0x30);
        let beg = hdr_sz + strd;
        buf[beg + 520..beg + 527].copy_from_slice(b"GTX 950");
        set(&mut buf, beg + 1300, 2 * 1024 * 1024);
        buf
    }
    #[test]
    fn t_v2_fie_and_32b_tim() {
        let buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        assert_eq!(&buf[..4], b"MHAM");
        let dec = prs(&buf).unwrap();
        assert_eq!(dec.hdr.poll_tm, 12345);
        assert_eq!(dec.ents[0].val, Some(42.5));
        assert_eq!(dec.ents[0].src_id, 0x30);
        assert_eq!(dec.ents[0].inst, Some(0));
        assert_eq!(dec.gpus[0].dev, "GTX 950");
        assert_eq!(dec.gpus[0].mem_kb, 2 * 1024 * 1024);
    }
    #[test]
    fn t_ext_siz_and_min_ver_use_dec_str() {
        let mut buf = fx(40, ENT_SZ + 12, GPU_ENT_SZ + 8);
        set(&mut buf, 4, 0x0002_0001);
        assert_eq!(prs(&buf).unwrap().gpus[0].dev, "GTX 950");
    }
    #[test]
    fn t_sen_and_non_val_are_una() {
        for val in [f32::MAX, f32::INFINITY, f32::NAN] {
            let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
            set(&mut buf, HDR_SZ + 1300, val.to_bits());
            assert_eq!(prs(&buf).unwrap().ents[0].val, None);
        }
    }
    #[test]
    fn t_glo_sou_and_neg_tim_are_pre() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, HDR_SZ + 1316, u32::MAX);
        set(&mut buf, 20, u32::MAX);
        let dec = prs(&buf).unwrap();
        assert_eq!(dec.ents[0].inst, None);
        assert_eq!(dec.hdr.poll_tm, -1);
    }
    #[test]
    fn t_tru_hea_and_pay_fai() {
        let buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        assert!(prs(&buf[..31]).is_err());
        assert!(prs(&buf[..buf.len() - 1]).is_err());
    }
    #[test]
    fn t_dea_and_wro_end_sig_fai() {
        for signature in [0xdead, 0x4d48_414d, 0] {
            let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
            set(&mut buf, 0, signature);
            assert!(prs(&buf).is_err());
        }
    }
    #[test]
    fn t_unk_ver_and_sma_str_fai() {
        for (fld, val) in [(4, 0x0003_0000), (8, 31), (16, 1323), (28, 1303)] {
            let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
            set(&mut buf, fld, val);
            assert!(prs(&buf).is_err());
        }
    }
    #[test]
    fn t_exc_lay_siz_is_rej_bef_all() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, 12, u32::MAX);
        set(&mut buf, 16, u32::MAX);
        assert!(Hdr::prs(&buf).is_err());
    }
    #[test]
    fn t_inv_gpu_ind_is_rej() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, HDR_SZ + 1316, 1);
        assert!(prs(&buf).is_err());
    }
    #[test]
    fn t_cpu_ins_is_not_a_gpu_ind_reg() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, HDR_SZ + 1320, 0x80);
        set(&mut buf, HDR_SZ + 1316, 15);
        let dec = prs(&buf).unwrap();
        assert_eq!(dec.ents[0].inst, Some(15));
        assert_eq!(dec.ents[0].scp(), "system");
    }
    #[test]
    fn t_unk_sou_ins_is_pre_wit_gpu_ass() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, HDR_SZ + 1320, 0xdeadbeef);
        set(&mut buf, HDR_SZ + 1316, 255);
        let dec = prs(&buf).unwrap();
        assert_eq!(dec.ents[0].inst, Some(255));
        assert_eq!(dec.ents[0].scp(), "unknown");
    }
    #[test]
    fn t_ans_tem_uni_are_dec_wit_gue_loc_nam() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        buf[HDR_SZ + 260..HDR_SZ + 263].copy_from_slice(b"\xb0C\0");
        assert_eq!(prs(&buf).unwrap().ents[0].unt, "\u{00b0}C");
    }
    #[test]
    fn t_emp_ini_sna_is_all() {
        let mut buf = fx(HDR_SZ, ENT_SZ, GPU_ENT_SZ);
        set(&mut buf, 12, 0);
        set(&mut buf, 16, 0);
        set(&mut buf, 24, 0);
        set(&mut buf, 28, 0);
        buf.truncate(HDR_SZ);
        let dec = prs(&buf).unwrap();
        assert!(dec.ents.is_empty());
        assert!(dec.gpus.is_empty());
    }
}
