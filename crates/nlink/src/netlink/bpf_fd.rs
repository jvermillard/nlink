//! A BPF program's file descriptor, as a TC filter or action holds it
//! (#710).

use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    sync::Arc,
};

/// `BPF_OBJ_GET`, from `enum bpf_cmd` in `include/uapi/linux/bpf.h`.
const BPF_OBJ_GET: libc::c_long = 7;

/// `union bpf_attr`'s `BPF_OBJ_*` member. The kernel requires every byte
/// past the command's last field to be zero, so the padding is a field.
#[repr(C)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
    _pad: u32,
}

/// A BPF program fd: a number the caller keeps open, or one nlink opened
/// from a pin, closed with the last clone.
#[derive(Debug, Clone)]
pub(crate) enum ProgFd {
    Raw(RawFd),
    Owned(Arc<OwnedFd>),
}

impl ProgFd {
    /// The fd number the kernel is sent.
    pub(crate) fn raw(&self) -> RawFd {
        match self {
            Self::Raw(fd) => *fd,
            Self::Owned(fd) => fd.as_raw_fd(),
        }
    }

    /// Open the program pinned at `path`. bpffs refuses `open(2)` on a
    /// pinned object (`bpffs_obj_open` returns `EIO`); the fd comes from
    /// `bpf(BPF_OBJ_GET)`.
    pub(crate) fn open_pinned(path: &Path) -> std::io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let attr = ObjAttr {
            pathname: path.as_ptr() as u64,
            bpf_fd: 0,
            file_flags: 0,
            path_fd: 0,
            _pad: 0,
        };
        // SAFETY: `attr` is a fully initialized `bpf_attr` prefix of the
        // size passed, and `path` outlives the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_OBJ_GET,
                &attr as *const ObjAttr,
                std::mem::size_of::<ObjAttr>(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the kernel just returned this fd, and nothing else owns it.
        Ok(Self::Owned(Arc::new(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_obj_attr_is_the_kernels_size_with_no_hidden_padding() {
        assert_eq!(std::mem::size_of::<ObjAttr>(), 24);
    }
}
