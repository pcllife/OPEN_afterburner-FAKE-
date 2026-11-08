// _io_
mod cm;
mod hm;
mod nv;
mod shm;

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    process::ExitCode,
};

fn lbl(txt: &str) -> String {
    txt.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}
fn show(snap: &hm::Snap, gpu_on: bool) {
    println!(
        "MAHM {}.{} | poll_unix={} | {} sources | {} GPUs",
        snap.hdr.ver >> 16,
        snap.hdr.ver & 0xffff,
        snap.hdr.poll_tm,
        snap.ents.len(),
        snap.gpus.len()
    );
    for (idx, gpu) in snap.gpus.iter().enumerate() {
        println!(
            "GPU {idx}: {} | family={} | memory={}",
            lbl(&gpu.dev),
            lbl(&gpu.fam),
            if gpu.mem_kb == 0 {
                "N/A".into()
            } else {
                format!("{} KiB", gpu.mem_kb)
            }
        );
        println!(
            "  id={} | driver={} | BIOS={}",
            lbl(&gpu.id),
            lbl(&gpu.drv),
            lbl(&gpu.bios)
        );
    }
    println!("SCOPE\tINSTANCE\tSOURCE_ID\tNAME\tVALUE\tUNITS\tRANGE\tFLAGS");
    for ent in &snap.ents {
        if gpu_on && ent.scp() != "gpu" {
            continue;
        }
        let gpu = ent
            .inst
            .map_or_else(|| "global".to_string(), |id| id.to_string());
        let val = ent
            .val
            .map_or_else(|| "N/A".to_string(), |v| format!("{v:.3}"));
        let lim = |v: Option<f32>| v.map_or_else(|| "N/A".to_string(), |v| format!("{v:.3}"));
        println!(
            "{}\t{gpu}\t{:#06x}\t{}\t{val}\t{}\t{}..{}\t{:#x}",
            ent.scp(),
            ent.src_id,
            lbl(&ent.name),
            lbl(&ent.unt),
            lim(ent.min_lim),
            lim(ent.max_lim),
            ent.flags
        );

        let _ = (&ent.loc_nm, &ent.loc_u, &ent.rec_fmt);
    }
}
fn show_nv(snap: &nv::Snap) {
    let ver = snap
        .drv_ver
        .map_or_else(|| "N/A".into(), |v| format!("{}.{:02}", v / 100, v % 100));
    println!(
        "Independent NVAPI | driver={} | branch={} | {} GPUs",
        ver,
        snap.drv_br.as_deref().unwrap_or("N/A"),
        snap.gpus.len()
    );
    for warn in &snap.warns {
        eprintln!("NVAPI: {}", lbl(warn));
    }
    for (idx, gpu) in snap.gpus.iter().enumerate() {
        println!("GPU {idx}: {}", lbl(&gpu.name));
        for (dom, val) in ["GPU", "FB", "VID", "BUS"].iter().zip(gpu.use_pct) {
            println!(
                "  {dom} usage: {}",
                val.map_or_else(|| "N/A".into(), |v| format!("{v}%"))
            );
        }
        let clk = |v: Option<f64>| v.map_or_else(|| "N/A".into(), |v| format!("{v:.3} MHz"));
        println!(
            "  Core clock: {} | Memory clock: {}",
            clk(gpu.gfx_mhz),
            clk(gpu.mem_mhz)
        );
        for sen in &gpu.temps {
            println!("  Temperature target {}: {} C", sen.tgt, sen.cel);
        }
        if gpu.temps.is_empty() {
            println!("  Temperature: N/A");
        }
        println!(
            "  Fan tachometer: {}",
            gpu.fan_rpm
                .map_or_else(|| "N/A".into(), |v| format!("{v} RPM"))
        );
        let mib = |v: Option<u32>| {
            v.map_or_else(|| "N/A".into(), |v| format!("{:.3} MiB", v as f64 / 1024.0))
        };
        println!(
            "  Dedicated framebuffer: {} | Currently available: {}",
            mib(gpu.ded_kib),
            mib(gpu.avail_kib)
        );
        for warn in &gpu.warns {
            eprintln!("GPU {idx}: {}", lbl(warn));
        }
    }
}
fn show_cm(s: &cm::Snap) {
    println!(
        "READ-ONLY MACM {}.{} | {} GPUs | master={} | flags={:#x} | settings_time={} | pending_command={:#x}",
        s.hdr.ver >> 16,
        s.hdr.ver & 0xffff,
        s.gpus.len(),
        s.hdr.mst_gpu,
        s.hdr.flags,
        s.hdr.set_tm,
        s.hdr.cmd
    );
    println!("Control snapshot only; reported ranges are NOT stability or safety guarantees.");
    println!("No settings, pending commands, voltages, power limits or fan modes are changed.");
    for (i, gpu) in s.gpus.iter().enumerate() {
        println!("GPU {i}: {} | capabilities={:#x}", lbl(&gpu.id), gpu.flags);
        println!("PARAMETER\tCURRENT\tMIN\tMAX\tDEFAULT\tUNITS\tRANGE_CHECK");
        for r in &gpu.rngs {
            let check = if !r.ord() {
                "unordered range"
            } else if !r.cur_in_rng() {
                "current outside range"
            } else if !r.dft_in_rng() {
                "default outside range"
            } else {
                "within reported range; not stability tested"
            };
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                r.name, r.cur, r.min, r.max, r.dft, r.unt, check
            );
        }
        if gpu.rngs.is_empty() {
            println!("No supported scalar controls reported (not zero-valued controls).");
        }
        if let Some(c) = &gpu.cv {
            println!(
                "VF curve: enabled={} points={} lock_index_plus_one={} power_tuples={} thermal_tuples={}",
                c.en, c.pts, c.lock_idx1, c.pwr_tp, c.thm_tp
            );
        } else {
            println!("VF curve: unavailable in this capability snapshot");
        }
    }
    println!(
        "Unsupported controls are omitted; command consumption does not prove hardware success. Snapshot is best-effort, not atomic."
    );
}

fn usage() {
    println!(
        "abx: read-only MAHM and independent NVIDIA monitor\n\
Usage:\n\
  abx monitor [--gpu-only]\n\
  abx nvapi\n\
  abx oc-info [--from <file.bin>]\n\
  abx oc-snapshot <new-file.bin>\n\
  abx snapshot <new-file.bin>\n\
  abx parse <file.bin> [--gpu-only]\n\
No direct RTCore IOCTLs, MACM writes, or overclock changes are performed."
    );
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => usage(),
        [cmd] if cmd == "oc-info" => show_cm(&cm::prs(&shm::cm_snap()?)?),
        [cmd, opt, path] if cmd == "oc-info" && opt == "--from" => {
            show_cm(&cm::prs(&fs::read(path)?)?)
        }
        [cmd, path] if cmd == "oc-snapshot" => {
            let buf = shm::cm_snap()?;
            let dec = cm::prs(&buf)?;
            let mut out = OpenOptions::new().write(true).create_new(true).open(path)?;
            out.write_all(&buf)?;
            println!(
                "Saved {} bytes / {} GPUs of READ-ONLY control data to {}",
                buf.len(),
                dec.gpus.len(),
                path
            );
        }

        [cmd] if cmd == "nvapi" => show_nv(&nv::snap()?),
        [help] if help == "--help" || help == "-h" || help == "help" => usage(),
        [cmd] if cmd == "monitor" => show(&hm::prs(&shm::snap()?)?, false),
        [cmd, opt] if cmd == "monitor" && opt == "--gpu-only" => {
            show(&hm::prs(&shm::snap()?)?, true)
        }
        [cmd, path] if cmd == "parse" => show(&hm::prs(&fs::read(path)?)?, false),
        [cmd, path, opt] if cmd == "parse" && opt == "--gpu-only" => {
            show(&hm::prs(&fs::read(path)?)?, true)
        }
        [cmd, path] if cmd == "snapshot" => {
            let buf = shm::snap()?;
            let dec = hm::prs(&buf)?;

            let mut out = OpenOptions::new().write(true).create_new(true).open(path)?;
            out.write_all(&buf)?;
            println!(
                "Saved {} bytes, {} sources and {} GPUs to {}",
                buf.len(),
                dec.ents.len(),
                dec.gpus.len(),
                path
            );
            println!("Snapshot is best-effort; the SDK mapping has no seqlock.");
        }
        _ => return Err("invalid arguments; use --help".into()),
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}
