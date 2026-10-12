//! [`NetnsCommand`]: a process spawned in a network namespace, with what a
//! lab needs around it (#521) — an `/etc/netns` overlay policy, the user to
//! run as once inside, the cgroup to start in, and a parent-death signal.
//!
//! ```no_run
//! # fn example() -> nlink::Result<()> {
//! use std::process::Command;
//! use nlink::netlink::namespace::{NetnsCommand, Overlay, SpawnUser};
//!
//! let mut cmd = Command::new("dnsmasq");
//! cmd.arg("--keep-in-foreground");
//! let child = NetnsCommand::new("lab-r1", cmd)?
//!     .etc_overlay(Overlay::BestEffort)
//!     .cgroup("/sys/fs/cgroup/lab/r1")
//!     .user(SpawnUser::new(1000, 1000))
//!     .pdeathsig(libc::SIGTERM)
//!     .spawn()?;
//! # let _ = child;
//! # Ok(())
//! # }
//! ```

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};

use super::{SpawnUser, live_named_path, open_path, path_to_cstring, prepare_etc_binds, sysfs_mount_flags};
use crate::{Error, Result};

/// What a spawned process gets of `/etc/netns/<name>/` (#521), the files
/// `ip netns exec` binds over `/etc` in a private mount namespace, with a
/// `/sys` remounted for the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Overlay {
    /// No mount namespace: the host's `/etc` and `/sys`, as
    /// [`spawn`](super::spawn) gives.
    #[default]
    Off,
    /// The overlay, or the spawn fails: [`spawn_with_etc`](super::spawn_with_etc)'s
    /// rules. An overlay the caller set up and did not get is an error.
    Strict,
    /// The overlay where the environment allows it, and never a failure
    /// for want of it.
    ///
    /// - A container runtime that refuses the private mount namespace
    ///   (`unshare(CLONE_NEWNS)`) or its `MS_SLAVE` remount leaves the
    ///   process with the host's `/etc` and `/sys`: nothing is bound into a
    ///   mount tree that propagates to the host.
    /// - The namespace's sysfs is mounted on top of `/sys`, not in place of
    ///   it. Strict detaches the old one first, and a kernel that then
    ///   refuses the new one — in a user namespace once no sysfs is fully
    ///   visible — would leave no `/sys`, so Strict fails there. On top,
    ///   a refused mount leaves the old `/sys`, stale but present.
    /// - A file whose bind is refused is left out.
    BestEffort,
}

/// A process spawned in a network namespace (#521). See the
/// [module docs](self).
#[derive(Debug)]
#[must_use = "a command does nothing until spawned"]
pub struct NetnsCommand {
    ns_fd: OwnedFd,
    /// The `ip netns` name, for `/etc/netns/<name>/`.
    name: Option<String>,
    cmd: Command,
    overlay: Overlay,
    user: Option<SpawnUser>,
    cgroup: Option<PathBuf>,
    pdeathsig: Option<libc::c_int>,
}

/// What [`NetnsCommand::prepare`] keeps open until the spawn returns; the
/// namespace fd stays in the command itself.
struct KeepOpen {
    _cgroup: Option<std::fs::File>,
}

impl NetnsCommand {
    /// `cmd`, to run in the namespace `ip netns` knows as `name`.
    pub fn new(name: &str, cmd: Command) -> Result<Self> {
        let path = live_named_path(name)?;
        Ok(Self::with_fd(OwnedFd::from(open_path(&path)?.file), Some(name.to_string()), cmd))
    }

    /// `cmd`, to run in the namespace at `path` (an nsfs file, such as
    /// `/proc/<pid>/ns/net`). It has no `/etc/netns` overlay to give.
    pub fn path(path: impl AsRef<Path>, cmd: Command) -> Result<Self> {
        Ok(Self::with_fd(OwnedFd::from(open_path(path.as_ref())?.file), None, cmd))
    }

    pub(crate) fn with_fd(ns_fd: OwnedFd, name: Option<String>, cmd: Command) -> Self {
        Self {
            ns_fd,
            name,
            cmd,
            overlay: Overlay::Off,
            user: None,
            cgroup: None,
            pdeathsig: None,
        }
    }

    /// The `/etc/netns/<name>/` overlay policy; [`Overlay::Off`] by
    /// default. A namespace with no name has no overlay to give.
    pub fn etc_overlay(mut self, overlay: Overlay) -> Self {
        self.overlay = overlay;
        self
    }

    /// Run as `user`, dropped to once inside the namespace and its mounts.
    /// `CommandExt::uid` cannot do this: std applies it before the
    /// `setns`, which then fails with `EPERM`.
    pub fn user(mut self, user: SpawnUser) -> Self {
        self.user = Some(user);
        self
    }

    /// Start the process in the cgroup (v2) at `dir`: it joins before it
    /// enters the namespace, so the processes it starts are in the cgroup
    /// from the first. Writing the pid after the spawn let them escape the
    /// limits.
    pub fn cgroup(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cgroup = Some(dir.into());
        self
    }

    /// The signal the process gets when the thread that spawned it ends
    /// (`PR_SET_PDEATHSIG`) — the thread, not the process.
    pub fn pdeathsig(mut self, signal: libc::c_int) -> Self {
        self.pdeathsig = Some(signal);
        self
    }

    /// Spawn it.
    pub fn spawn(mut self) -> Result<Child> {
        let keep = self.prepare()?;
        let child = self.cmd.spawn().map_err(Error::Io);
        drop(keep);
        child
    }

    /// Run it to completion and collect its output.
    pub fn output(mut self) -> Result<Output> {
        let keep = self.prepare()?;
        let output = self.cmd.output().map_err(Error::Io);
        drop(keep);
        output
    }

    /// Install everything the child does between `fork` and `exec`: only
    /// raw syscalls, on what was computed here first.
    fn prepare(&mut self) -> Result<KeepOpen> {
        let binds = match (self.overlay, &self.name) {
            (Overlay::Off, _) => Vec::new(),
            (_, Some(name)) => prepare_etc_binds(name)?,
            (_, None) => {
                return Err(Error::InvalidMessage(
                    "an /etc/netns overlay needs a namespace opened by name".into(),
                ));
            }
        };
        let cgroup = match &self.cgroup {
            Some(dir) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join("cgroup.procs"))
                    .map_err(|e| Error::InvalidMessage(format!("cgroup {}: {e}", dir.display())))?,
            ),
            None => None,
        };
        let ns_raw = self.ns_fd.as_raw_fd();
        let cgroup_raw = cgroup.as_ref().map(|f| f.as_raw_fd());
        let pdeathsig = self.pdeathsig;
        let strict = self.overlay == Overlay::Strict;
        let ns_name = CString::new(self.name.clone().unwrap_or_default())
            .map_err(|_| Error::InvalidMessage("null byte in namespace name".into()))?;
        let c_root = path_to_cstring(Path::new("/"))?;
        let c_none = CString::new("none").expect("no null byte");
        let c_sys = path_to_cstring(Path::new("/sys"))?;
        let c_sysfs = CString::new("sysfs").expect("no null byte");

        // SAFETY: only raw syscalls run in the child — write, prctl,
        // setns, unshare, mount, umount2, statfs64 — on data computed
        // above and moved into the closure; nothing allocates.
        unsafe {
            self.cmd.pre_exec(move || {
                let err = std::io::Error::last_os_error;
                // The cgroup first, so everything after is in it.
                if let Some(fd) = cgroup_raw
                    && libc::write(fd, b"0".as_ptr().cast(), 1) != 1
                {
                    return Err(err());
                }
                if let Some(sig) = pdeathsig
                    && libc::prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong, 0, 0, 0) != 0
                {
                    return Err(err());
                }
                if libc::setns(ns_raw, libc::CLONE_NEWNET) != 0 {
                    return Err(err());
                }
                if binds.is_empty() {
                    return Ok(());
                }
                // A private mount namespace, its tree a slave of the
                // host's. Refused, best effort runs with the host's /etc:
                // a bind into a tree that propagates would reach the host.
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return if strict { Err(err()) } else { Ok(()) };
                }
                if libc::mount(
                    c_none.as_ptr(),
                    c_root.as_ptr(),
                    std::ptr::null(),
                    libc::MS_SLAVE | libc::MS_REC,
                    std::ptr::null(),
                ) != 0
                {
                    return if strict { Err(err()) } else { Ok(()) };
                }
                // `/sys` for the namespace, as `spawn_with_etc` does it
                // (#282, #334): never none, never refused over a stale one.
                // Best effort mounts it on top instead of detaching first,
                // so a refused mount can only leave the old one.
                let detached = strict && libc::umount2(c_sys.as_ptr(), libc::MNT_DETACH) == 0;
                let mut flags: libc::c_ulong = 0;
                if !detached {
                    let mut st: libc::statfs64 = std::mem::zeroed();
                    if libc::statfs64(c_sys.as_ptr(), &mut st) == 0 {
                        flags = sysfs_mount_flags(st.f_flags as libc::c_ulong);
                    }
                }
                if libc::mount(ns_name.as_ptr(), c_sys.as_ptr(), c_sysfs.as_ptr(), flags, std::ptr::null()) != 0
                    && detached
                {
                    return Err(err());
                }
                for (src, dst) in &binds {
                    if libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
                        != 0
                        && strict
                    {
                        return Err(err());
                    }
                }
                Ok(())
            });
        }
        if let Some(user) = &self.user {
            user.install(&mut self.cmd);
        }
        Ok(KeepOpen { _cgroup: cgroup })
    }
}

/// Whether [`Overlay::Strict`] can work here (#521): a private mount
/// namespace (`unshare(CLONE_NEWNS)`) and its `MS_SLAVE` remount, which
/// container runtimes commonly deny, a fresh sysfs in place of `/sys`,
/// which a rootless container's user namespace refuses, and a bind over
/// `/etc`. Probed once, by a child that does all of it in a mount namespace
/// of its own and exits. Where it is false, [`Overlay::BestEffort`] gives
/// what the environment allows.
pub fn etc_overlay_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let c_root = CString::new("/").expect("no null byte");
        let c_none = CString::new("none").expect("no null byte");
        let c_sys = CString::new("/sys").expect("no null byte");
        let c_sysfs = CString::new("sysfs").expect("no null byte");
        let c_etc = CString::new("/etc").expect("no null byte");
        let mut cmd = Command::new("true");
        // SAFETY: raw syscalls only, on CStrings made before the fork.
        unsafe {
            cmd.pre_exec(move || {
                let err = std::io::Error::last_os_error;
                if libc::unshare(libc::CLONE_NEWNS) != 0
                    || libc::mount(
                        c_none.as_ptr(),
                        c_root.as_ptr(),
                        std::ptr::null(),
                        libc::MS_SLAVE | libc::MS_REC,
                        std::ptr::null(),
                    ) != 0
                {
                    return Err(err());
                }
                // Strict's `/sys` step: detach, then mount afresh.
                let detached = libc::umount2(c_sys.as_ptr(), libc::MNT_DETACH) == 0;
                let mut flags: libc::c_ulong = 0;
                if !detached {
                    let mut st: libc::statfs64 = std::mem::zeroed();
                    if libc::statfs64(c_sys.as_ptr(), &mut st) == 0 {
                        flags = sysfs_mount_flags(st.f_flags as libc::c_ulong);
                    }
                }
                if libc::mount(c_sysfs.as_ptr(), c_sys.as_ptr(), c_sysfs.as_ptr(), flags, std::ptr::null()) != 0
                    && detached
                {
                    return Err(err());
                }
                if libc::mount(c_etc.as_ptr(), c_etc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
                    return Err(err());
                }
                Ok(())
            });
        }
        cmd.status().is_ok_and(|s| s.success())
    })
}
