//! launchd socket activation: launchd binds :53 for us and keeps the sockets
//! open across restarts.

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

extern "C" {
    fn launch_activate_socket(name: *const libc::c_char, fds: *mut *mut libc::c_int, cnt: *mut libc::size_t) -> libc::c_int;
}

pub enum Activation {
    Fds(Vec<RawFd>),
    /// Not started by launchd (or no such socket in the plist).
    NotManaged,
}

pub fn activate(name: &str) -> io::Result<Activation> {
    let c = CString::new(name).unwrap();
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut cnt: libc::size_t = 0;
    let rc = unsafe { launch_activate_socket(c.as_ptr(), &mut fds, &mut cnt) };
    match rc {
        0 => {
            let v = unsafe { std::slice::from_raw_parts(fds, cnt) }.to_vec();
            unsafe { libc::free(fds as *mut libc::c_void) };
            Ok(Activation::Fds(v))
        }
        libc::ESRCH | libc::ENOENT => Ok(Activation::NotManaged),
        e => Err(io::Error::from_raw_os_error(e)),
    }
}
