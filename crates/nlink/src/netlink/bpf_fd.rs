//! A BPF program's file descriptor, as a TC filter or action holds it
//! (#710).

use std::{
    ffi::CString,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
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

/// A BPF program fd: a number the caller keeps open (`fd <n>` in the
/// tc(8)-syntax parsers), or one nlink holds — a duplicate of the
/// caller's, or opened from a pin — closed with the last clone.
#[derive(Debug, Clone)]
pub(crate) enum ProgFd {
    Raw(RawFd),
    Owned(Arc<OwnedFd>),
    /// Duplicating the caller's fd failed; reported when the request is
    /// built.
    Failed(Arc<str>),
}

impl ProgFd {
    /// A duplicate of `fd`, so the caller's can be closed (#532).
    pub(crate) fn dup(fd: impl AsFd) -> Self {
        match fd.as_fd().try_clone_to_owned() {
            Ok(fd) => Self::Owned(Arc::new(fd)),
            Err(e) => Self::Failed(format!("bpf: duplicating the program fd: {e}").into()),
        }
    }

    /// The fd number the kernel is sent.
    pub(crate) fn raw(&self) -> crate::Result<RawFd> {
        match self {
            Self::Raw(fd) => Ok(*fd),
            Self::Owned(fd) => Ok(fd.as_raw_fd()),
            Self::Failed(e) => Err(crate::Error::InvalidMessage(e.to_string())),
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

    /// #532: a program fd given as `AsFd` is duplicated, so the caller's
    /// can close before the request is sent.
    #[test]
    fn a_duplicate_outlives_the_callers_fd() {
        use std::os::unix::fs::MetadataExt;
        let file = std::fs::File::open("/dev/null").unwrap();
        let want = file.metadata().unwrap().ino();
        let caller = file.as_raw_fd();
        let fd = ProgFd::dup(&file);
        drop(file);
        let ProgFd::Owned(held) = &fd else { panic!("{fd:?}") };
        assert_ne!(fd.raw().unwrap(), caller);
        let held = std::fs::File::from(held.try_clone().unwrap());
        assert_eq!(held.metadata().unwrap().ino(), want);
    }
}
