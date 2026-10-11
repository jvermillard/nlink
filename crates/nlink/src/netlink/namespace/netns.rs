//! An owned network namespace handle (#520).
//!
//! [`Netns`] owns an open fd to a namespace, so the namespace it names
//! cannot change under it: a namespace deleted and recreated under the same
//! name is a different one, with a different [`NetnsId`]. Everything that
//! needs "the namespace" — a connection, a socket, a closure run inside it —
//! derives from the fd, not from a name or pid looked up again.
//!
//! [`NetnsRef`] is the owned, serializable description of where a namespace
//! is (`Named`, `Path`, `Pid`, or the caller's own), for configs and state
//! files; [`NetnsRef::open`] turns it into a [`Netns`].

use std::{
    fmt,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{NamespaceSpec, live_named_path, namespace_open_error};
use crate::netlink::{
    connection::Connection,
    error::{Error, Result},
    protocol::{
        AsyncProtocolInit, ProtocolState,
        construction::{AsyncConstructible, SyncConstructible},
    },
    socket::NetlinkSocket,
};

/// `NS_GET_NSTYPE` (`_IO(0xb7, 0x3)`, Linux 4.11): the `CLONE_NEW*` type of
/// the namespace an nsfs fd names.
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
/// `PIDFD_GET_NET_NAMESPACE` (`_IO(0xff, 4)`, Linux 6.11): an fd for the
/// network namespace of the process a pidfd names.
const PIDFD_GET_NET_NAMESPACE: libc::c_ulong = 0xff04;

/// A network namespace's identity: the device and inode of its nsfs file,
/// as `stat` reports them and as `readlink /proc/<pid>/ns/net` prints the
/// inode (`net:[4026531840]`).
///
/// Two handles to one namespace have the same id however they were opened;
/// a namespace deleted and recreated under the same name has a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetnsId {
    dev: u64,
    ino: u64,
}

impl NetnsId {
    /// The id of the namespace `fd` names.
    pub fn of(fd: impl AsFd) -> Result<Self> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes a `stat` into the buffer on success, and the
        // fd is borrowed for the call.
        let ret = unsafe { libc::fstat(fd.as_fd().as_raw_fd(), st.as_mut_ptr()) };
        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: fstat returned 0, so the struct is initialized.
        let st = unsafe { st.assume_init() };
        Ok(Self {
            dev: st.st_dev,
            ino: st.st_ino,
        })
    }

    /// The nsfs device number.
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// The namespace's inode number, as `/proc/<pid>/ns/net` prints it.
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

impl fmt::Display for NetnsId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "net:[{}]", self.ino)
    }
}

/// An open network namespace.
///
/// It owns an fd to the namespace, which keeps the namespace alive while
/// the handle exists, even if its name is deleted: interfaces in it live
/// on. Open one with [`open`](Self::open) (an `ip netns` name),
/// [`from_path`](Self::from_path), [`from_pid`](Self::from_pid),
/// [`from_pidfd`](Self::from_pidfd), [`current`](Self::current) or
/// [`init`](Self::init), or make one with [`create`](Self::create).
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::namespace::Netns;
/// use nlink::{Connection, Route};
///
/// let ns = Netns::open("myns")?;
/// let conn: Connection<Route> = ns.connection()?;
/// let links = conn.get_links().await?;
///
/// // Code that needs to be inside the namespace, on a thread of its own.
/// let net_dev = ns.run(|| std::fs::read_to_string("/proc/thread-self/net/dev"))??;
/// # let _ = (links, net_dev);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Netns {
    fd: OwnedFd,
    id: NetnsId,
    name: Option<Arc<str>>,
    label: Arc<str>,
}

impl Netns {
    /// Open the namespace `ip netns` knows as `name` (`/var/run/netns/<name>`).
    ///
    /// # Errors
    ///
    /// [`Error::NamespaceNotFound`] (`is_not_found()`) when there is no
    /// live namespace by that name: no marker, or a stale marker with no
    /// mount behind it.
    pub fn open(name: &str) -> Result<Self> {
        let path = live_named_path(name)?;
        let mut ns = Self::open_nsfs(&path, name)?;
        ns.name = Some(Arc::from(name));
        Ok(ns)
    }

    /// Open the namespace at `path`: a bind-mounted marker, a
    /// `/proc/<pid>/ns/net`, or any other nsfs file of a network namespace.
    ///
    /// # Errors
    ///
    /// [`Error::NamespaceNotFound`] when nothing is at `path`, and an
    /// invalid-argument error when it is not a network namespace.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        Self::open_nsfs(path, &path.display().to_string())
    }

    /// Open the network namespace of process `pid`.
    ///
    /// A pid can be reused once the process exits. If the process might be
    /// gone, open its namespace from a pidfd with
    /// [`from_pidfd`](Self::from_pidfd), which cannot be reused.
    pub fn from_pid(pid: u32) -> Result<Self> {
        Self::open_nsfs(
            Path::new(&format!("/proc/{pid}/ns/net")),
            &format!("pid {pid}"),
        )
    }

    /// Open the network namespace of the process `pidfd` names
    /// (`pidfd_open(2)`).
    ///
    /// Asks the pidfd itself (`PIDFD_GET_NET_NAMESPACE`, Linux 6.11). On an
    /// older kernel it reads the pid from `/proc/self/fdinfo`, opens that
    /// process's namespace, and then checks the pidfd still names a live
    /// process, so a reused pid cannot hand back someone else's namespace.
    pub fn from_pidfd(pidfd: impl AsFd) -> Result<Self> {
        let pidfd = pidfd.as_fd();
        // SAFETY: the ioctl takes no argument and returns a new fd or -1.
        let fd = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_NET_NAMESPACE as _, 0) };
        if fd >= 0 {
            // SAFETY: the kernel returned a fresh fd that nothing else owns.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            return Self::from_owned(fd, "pidfd".into(), None);
        }
        let err = std::io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) {
            return Err(Error::Io(err));
        }
        let pid = pidfd_pid(pidfd)?;
        let ns = Self::from_pid(pid)?;
        // SAFETY: signal 0 checks for existence and sends nothing.
        let alive = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if alive < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(ns)
    }

    /// The calling thread's network namespace.
    pub fn current() -> Result<Self> {
        Self::open_nsfs(Path::new("/proc/thread-self/ns/net"), "current")
    }

    /// The initial network namespace, the one PID 1 is in. Opening it needs
    /// the privilege to inspect PID 1 (root, or `CAP_SYS_PTRACE`).
    pub fn init() -> Result<Self> {
        Self::open_nsfs(Path::new("/proc/1/ns/net"), "init")
    }

    /// Create a namespace `ip netns` will know as `name`, and open it.
    ///
    /// See [`create`](super::create) for what is created and the errors.
    pub fn create(name: &str) -> Result<Self> {
        super::create(name)?;
        Self::open(name)
    }

    /// Delete this namespace's `ip netns` name, as `ip netns delete` does.
    ///
    /// Only a namespace opened or created by name has one. The name is
    /// deleted only while it still names *this* namespace; if it was
    /// deleted and recreated since, the call fails and the new one is left
    /// alone. The namespace itself goes once nothing holds it: no process,
    /// no socket, no other handle.
    pub fn delete(self) -> Result<()> {
        let Some(name) = self.name.clone() else {
            return Err(Error::InvalidMessage(format!(
                "namespace {}: only a namespace opened by name can be deleted",
                self.label
            )));
        };
        let now = Self::open(&name)?;
        if now.id != self.id {
            return Err(Error::InvalidMessage(format!(
                "namespace {name}: the name now names another namespace ({}, not {}); \
                 not deleting it",
                now.id, self.id
            )));
        }
        drop(now);
        drop(self);
        super::delete(&name)
    }

    /// The namespace's identity.
    pub fn id(&self) -> NetnsId {
        self.id
    }

    /// The `ip netns` name, when it was opened or created by one.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// What it was opened as, for messages: the name, the path, `pid 42`,
    /// `current`, `init` or `pidfd`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Run `f` on a thread of its own inside the namespace, and return what
    /// it returns.
    ///
    /// The thread enters the namespace, runs `f` and exits, so there is
    /// nothing to switch back: the calling thread, and any runtime it
    /// belongs to, never leaves its namespace. `f` may borrow from the
    /// caller. Entering a namespace needs `CAP_SYS_ADMIN` over it; a thread
    /// already in it (the caller's own namespace) does not enter it again.
    ///
    /// # Errors
    ///
    /// An I/O error when the thread cannot be made or cannot enter the
    /// namespace, and an error when `f` panics.
    pub fn run<T: Send>(&self, f: impl FnOnce() -> T + Send) -> Result<T> {
        let fd = self.fd.as_fd();
        let target = self.id;
        std::thread::scope(|scope| {
            let worker = std::thread::Builder::new()
                .name("nlink-netns".into())
                .spawn_scoped(scope, move || -> Result<T> {
                    // A new thread starts in its creator's namespace, and
                    // setns refuses even that one without CAP_SYS_ADMIN.
                    let here = Netns::current().map(|n| n.id).ok();
                    // SAFETY: setns switches only this thread, which exits
                    // when `f` returns.
                    if here != Some(target)
                        && unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) } < 0
                    {
                        return Err(Error::Io(std::io::Error::last_os_error()));
                    }
                    Ok(f())
                })
                .map_err(Error::Io)?;
            worker.join().unwrap_or_else(|_| {
                Err(Error::InvalidMessage(format!(
                    "namespace {}: the closure panicked",
                    self.label
                )))
            })
        })
    }

    /// A socket in the namespace: `socket(domain, ty | SOCK_CLOEXEC,
    /// protocol)` made on a thread inside it. A socket stays in the
    /// namespace it was made in, so this is how to capture with `AF_PACKET`
    /// or connect over TCP from inside the namespace without a process
    /// there.
    ///
    /// ```no_run
    /// # fn example() -> nlink::Result<()> {
    /// use std::net::UdpSocket;
    /// use nlink::netlink::namespace::Netns;
    ///
    /// let ns = Netns::open("myns")?;
    /// let fd = ns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    /// let socket = UdpSocket::from(fd);
    /// socket.send_to(b"ping", "10.0.0.2:9")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn socket(&self, domain: i32, ty: i32, protocol: i32) -> Result<OwnedFd> {
        self.run(|| {
            // SAFETY: socket(2) returns a fresh fd or -1.
            let fd = unsafe { libc::socket(domain, ty | libc::SOCK_CLOEXEC, protocol) };
            if fd < 0 {
                Err(Error::Io(std::io::Error::last_os_error()))
            } else {
                // SAFETY: the fd was just made and nothing else owns it.
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        })?
    }

    /// A new netlink connection in the namespace.
    ///
    /// For the generic-netlink families that resolve their id
    /// asynchronously (WireGuard, ethtool, …), use
    /// [`connection_async`](Self::connection_async).
    pub fn connection<P: ProtocolState + Default + SyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        Connection::new_in_namespace_fd(&self.fd)
    }

    /// A new connection to a generic-netlink family in the namespace, its
    /// family id resolved inside it.
    pub async fn connection_async<P: AsyncProtocolInit + AsyncConstructible>(
        &self,
    ) -> Result<Connection<P>> {
        let socket = NetlinkSocket::new_in_namespace_fd(P::PROTOCOL, &self.fd)?;
        let state = P::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }

    /// Another handle to the same namespace, with its own fd.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone().map_err(Error::Io)?,
            id: self.id,
            name: self.name.clone(),
            label: self.label.clone(),
        })
    }

    fn open_nsfs(path: &Path, label: &str) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| namespace_open_error(path, e))?;
        Self::from_owned(OwnedFd::from(file), label.into(), None)
    }

    fn from_owned(fd: OwnedFd, label: Arc<str>, name: Option<Arc<str>>) -> Result<Self> {
        // SAFETY: the ioctl takes no argument; on an nsfs fd it returns the
        // namespace's CLONE_NEW* type.
        let ty = unsafe { libc::ioctl(fd.as_raw_fd(), NS_GET_NSTYPE as _, 0) };
        if ty < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::InvalidMessage(format!(
                "{label}: not a namespace file ({err})"
            )));
        }
        if ty != libc::CLONE_NEWNET {
            return Err(Error::InvalidMessage(format!(
                "{label}: not a network namespace"
            )));
        }
        let id = NetnsId::of(&fd)?;
        Ok(Self {
            fd,
            id,
            name,
            label,
        })
    }
}

impl AsFd for Netns {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Two handles are equal when they name the same namespace.
impl PartialEq for Netns {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Netns {}

impl std::hash::Hash for Netns {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl fmt::Display for Netns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.label, self.id)
    }
}

/// The pid a pidfd names, from its `/proc/self/fdinfo` entry.
fn pidfd_pid(pidfd: BorrowedFd<'_>) -> Result<u32> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let info = std::fs::read_to_string(&path).map_err(Error::Io)?;
    let pid = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .map(str::trim)
        .and_then(|p| p.parse::<i64>().ok());
    match pid {
        Some(p) if p > 0 => Ok(p as u32),
        // -1: the process has exited (and been reaped).
        Some(_) => Err(Error::Io(std::io::Error::from_raw_os_error(libc::ESRCH))),
        None => Err(Error::InvalidMessage(format!("{path}: not a pidfd"))),
    }
}

/// Where a network namespace is, as configs and state files say it.
///
/// Owned, `Clone + Eq + Hash`, and with the `serde` feature serializable:
/// `"default"`, `{"named": "red"}`, `{"path": "/proc/42/ns/net"}`,
/// `{"pid": 42}`. [`open`](Self::open) gives the [`Netns`] it describes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum NetnsRef {
    /// The namespace of whoever opens it.
    #[default]
    Default,
    /// A namespace `ip netns` knows by this name.
    Named(String),
    /// The namespace at this nsfs path.
    Path(PathBuf),
    /// The namespace of this process.
    Pid(u32),
}

impl NetnsRef {
    /// Open the namespace this describes. `Default` is the calling thread's
    /// namespace.
    pub fn open(&self) -> Result<Netns> {
        match self {
            Self::Default => Netns::current(),
            Self::Named(name) => Netns::open(name),
            Self::Path(path) => Netns::from_path(path),
            Self::Pid(pid) => Netns::from_pid(*pid),
        }
    }

    /// `true` for [`NetnsRef::Default`].
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }
}

impl fmt::Display for NetnsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Named(name) => f.write_str(name),
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Pid(pid) => write!(f, "pid {pid}"),
        }
    }
}

impl From<&NamespaceSpec<'_>> for NetnsRef {
    fn from(spec: &NamespaceSpec<'_>) -> Self {
        match spec {
            NamespaceSpec::Default => Self::Default,
            NamespaceSpec::Named(name) => Self::Named((*name).to_string()),
            NamespaceSpec::Path(path) => Self::Path(path.to_path_buf()),
            NamespaceSpec::Pid(pid) => Self::Pid(*pid),
        }
    }
}

impl From<NamespaceSpec<'_>> for NetnsRef {
    fn from(spec: NamespaceSpec<'_>) -> Self {
        Self::from(&spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One namespace, opened two ways, has one id; a thread inside it sees
    /// the same one. None of this needs privileges.
    #[test]
    fn the_same_namespace_has_the_same_id_however_it_is_opened() {
        let current = Netns::current().unwrap();
        let by_path = Netns::from_path("/proc/self/ns/net").unwrap();
        assert_eq!(current.id(), by_path.id());
        assert_eq!(current, by_path);
        let seen = current
            .run(|| Netns::current().map(|n| n.id()))
            .unwrap()
            .unwrap();
        assert_eq!(seen, current.id());
        assert!(
            current.to_string().starts_with("current (net:["),
            "{current}"
        );
    }

    /// `run` can borrow from the caller.
    #[test]
    fn run_borrows() {
        let ns = Netns::current().unwrap();
        let words = ["a", "b"];
        let n = ns.run(|| words.len()).unwrap();
        assert_eq!(n, 2);
    }

    /// A file that is not a namespace, or a namespace that is not a
    /// network one, is refused.
    #[test]
    fn only_a_network_namespace_opens() {
        let err = Netns::from_path("/proc/self/status").unwrap_err();
        assert!(err.to_string().contains("not a namespace file"), "{err}");
        let err = Netns::from_path("/proc/self/ns/uts").unwrap_err();
        assert!(err.to_string().contains("not a network namespace"), "{err}");
        let err = Netns::from_path("/nonexistent/ns").unwrap_err();
        assert!(err.is_not_found(), "{err}");
    }

    /// A pidfd of this process opens this namespace, on any kernel.
    #[test]
    fn a_pidfd_opens_its_process_namespace() {
        // SAFETY: pidfd_open returns a fresh fd or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        if fd < 0 {
            // Kernels before 5.3 have no pidfds.
            return;
        }
        // SAFETY: the fd was just made and nothing else owns it.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let ns = Netns::from_pidfd(&pidfd).unwrap();
        assert_eq!(ns.id(), Netns::current().unwrap().id());
        assert_eq!(pidfd_pid(pidfd.as_fd()).unwrap(), std::process::id());
    }

    #[test]
    fn netns_ref_displays_and_opens_default() {
        assert_eq!(NetnsRef::Named("red".into()).to_string(), "red");
        assert_eq!(NetnsRef::Pid(7).to_string(), "pid 7");
        assert_eq!(NetnsRef::default().to_string(), "default");
        let spec = NamespaceSpec::Named("red");
        assert_eq!(NetnsRef::from(&spec), NetnsRef::Named("red".into()));
        let here = NetnsRef::Default.open().unwrap();
        assert_eq!(here.id(), Netns::current().unwrap().id());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn netns_ref_serde_shape() {
        let refs = [
            NetnsRef::Default,
            NetnsRef::Named("red".into()),
            NetnsRef::Path("/proc/42/ns/net".into()),
            NetnsRef::Pid(42),
        ];
        let json = serde_json::to_string(&refs).unwrap();
        assert_eq!(
            json,
            r#"["default",{"named":"red"},{"path":"/proc/42/ns/net"},{"pid":42}]"#
        );
        let back: Vec<NetnsRef> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, refs);
    }
}
