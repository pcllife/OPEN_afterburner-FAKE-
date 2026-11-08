// _io_
#[cfg(windows)]
mod plat {
    use crate::hm;
    use std::{ffi::c_void, io, marker::PhantomData, ptr};

    const FILE_MAP_READ: u32 = 0x0004;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenFileMappingW(acc: u32, inh: i32, name: *const u16) -> *mut c_void;
        fn MapViewOfFile(
            mp: *mut c_void,
            acc: u32,
            off_hi: u32,
            off_lo: u32,
            buf: usize,
        ) -> *mut c_void;
        fn UnmapViewOfFile(addr: *const c_void) -> i32;
        fn CloseHandle(hnd: *mut c_void) -> i32;
    }
    struct Map(*mut c_void);
    impl Drop for Map {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct View<'a> {
        addr: *const u8,
        len: usize,
        _mp: PhantomData<&'a Map>,
    }
    impl Drop for View<'_> {
        fn drop(&mut self) {
            unsafe {
                UnmapViewOfFile(self.addr.cast());
            }
        }
    }
    impl Map {
        fn view(&self, len: usize) -> io::Result<View<'_>> {
            let addr = unsafe { MapViewOfFile(self.0, FILE_MAP_READ, 0, 0, len) };
            if addr.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(View {
                addr: addr.cast(),
                len,
                _mp: PhantomData,
            })
        }
    }
    impl View<'_> {
        fn cp_pre(&self, len: usize) -> Vec<u8> {
            assert!(len <= self.len);

            (0..len)
                .map(|idx| unsafe { ptr::read_volatile(self.addr.add(idx)) })
                .collect()
        }
    }
    fn bad_data(error: impl std::fmt::Display) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }
    // _guard_
    fn snap_nm(
        name: &str,
        hdr_sz: usize,
        req: impl Fn(&[u8]) -> io::Result<usize>,
    ) -> io::Result<Vec<u8>> {
        let wstr: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let hnd = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wstr.as_ptr()) };
        if hnd.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{name} is unavailable: {}. No producer is started or reconfigured.",
                    io::Error::last_os_error()
                ),
            ));
        }
        let mp = Map(hnd);
        for _ in 0..3 {
            let fst = mp.view(hdr_sz)?.cp_pre(hdr_sz);
            let len = req(&fst)?;
            let view = mp.view(len)?;
            let buf = view.cp_pre(len);
            let aft = view.cp_pre(hdr_sz);
            if buf[..hdr_sz] == fst && aft == fst {
                return Ok(buf);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("{name} header changed while copying; retry later"),
        ))
    }
    pub fn snap() -> io::Result<Vec<u8>> {
        snap_nm("MAHMSharedMemory", hm::HDR_SZ, |buf| {
            hm::Hdr::prs(buf)
                .and_then(|h| h.req_len())
                .map_err(bad_data)
        })
    }
    pub fn cm_snap() -> io::Result<Vec<u8>> {
        snap_nm("MACMSharedMemory", crate::cm::HDR_SZ, |buf| {
            crate::cm::Hdr::prs(buf)
                .and_then(|h| h.req_len())
                .map_err(bad_data)
        })
    }
}

#[cfg(windows)]
pub use plat::{cm_snap, snap};

#[cfg(not(windows))]
pub fn snap() -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "live MAHM mapping is Windows-only; use the parse command for saved snapshots",
    ))
}

#[cfg(not(windows))]
pub fn cm_snap() -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "live MACM inspection is Windows-only; use oc-info --from for an offline snapshot",
    ))
}
