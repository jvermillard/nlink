//! `Netns`, the owned namespace handle (#520): identity however a namespace
//! is opened, work done inside it, and a delete that cannot hit the wrong
//! namespace.

use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::link::DummyLink;
use nlink::netlink::namespace::{self, Netns, NetnsRef};
use nlink::{Connection, Route};

use crate::common::TestNamespace;

/// A name, its marker path, a process inside and a pidfd of that process
/// all open the same namespace, and it is not the caller's.
#[tokio::test]
async fn one_namespace_however_it_is_opened() -> nlink::Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("netns-id")?;
    let by_name = Netns::open(ns.name())?;
    let by_path = Netns::from_path(format!("/var/run/netns/{}", ns.name()))?;
    assert_eq!(by_name.id(), by_path.id());
    assert_ne!(by_name.id(), Netns::current()?.id());
    assert_eq!(by_name.name(), Some(ns.name()));
    let by_ref = NetnsRef::Named(ns.name().to_string()).open()?;
    assert_eq!(by_ref, by_name);

    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("5");
    let mut child = namespace::spawn(ns.name(), cmd)?;
    let by_pid = Netns::from_pid(child.id())?;
    // SAFETY: pidfd_open returns a fresh fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
    assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: the fd was just made and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let by_pidfd = Netns::from_pidfd(&pidfd)?;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(by_pid.id(), by_name.id());
    assert_eq!(by_pidfd.id(), by_name.id());
    Ok(())
}

/// `run` and `socket` work inside the namespace: the thread sees its
/// devices, and a socket from it can bind an address only it has.
#[tokio::test]
async fn run_and_socket_are_inside() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("netns-run")?;
    let netns = Netns::open(ns.name())?;
    let conn: Connection<Route> = netns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.set_link_up("d0").await?;
    let addr = std::net::Ipv4Addr::new(10, 77, 0, 1);
    conn.add_address(Ipv4Address::new("d0", addr, 24)).await?;

    let net_dev = netns.run(|| std::fs::read_to_string("/proc/thread-self/net/dev"))??;
    assert!(net_dev.contains("d0:"), "{net_dev}");

    let socket = std::net::UdpSocket::from(netns.socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?);
    let bound = socket2_bind(&socket, std::net::SocketAddrV4::new(addr, 0));
    assert!(bound.is_ok(), "bind inside the namespace: {bound:?}");
    let outside = std::net::UdpSocket::bind((addr, 0));
    assert!(outside.is_err(), "the host should not have {addr}");
    Ok(())
}

/// Bind an already-made socket (`UdpSocket::bind` makes its own).
fn socket2_bind(socket: &std::net::UdpSocket, addr: std::net::SocketAddrV4) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: a valid sockaddr_in of the right length, on a live fd.
    let ret = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// A handle keeps its namespace, and its devices, alive after the name is
/// deleted. Deleting through a handle whose name was deleted and recreated
/// since is refused, and the new namespace is left alone.
#[tokio::test]
async fn delete_never_hits_a_recreated_namespace() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    let name = format!("nlk-netns-del-{}", std::process::id());
    let first = Netns::create(&name)?;
    let conn: Connection<Route> = first.connection()?;
    conn.add_link(DummyLink::new("held")).await?;

    namespace::delete(&name)?;
    assert!(Netns::open(&name).is_err_and(|e| e.is_not_found()));
    assert!(
        conn.get_link_by_name("held").await?.is_some(),
        "the handle keeps the namespace and its devices"
    );

    let second = Netns::create(&name)?;
    assert_ne!(second.id(), first.id());
    let err = first
        .delete()
        .expect_err("the name names another namespace now");
    assert!(err.to_string().contains("not deleting"), "{err}");
    assert!(
        Netns::open(&name).is_ok(),
        "the new namespace is still there"
    );

    second.delete()?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(Netns::open(&name).is_err_and(|e| e.is_not_found()));
    Ok(())
}

/// A generic-netlink family resolves inside the namespace.
#[tokio::test]
async fn an_async_family_connects_inside() -> nlink::Result<()> {
    use nlink::netlink::Wireguard;
    nlink::require_root!();
    nlink::require_modules!("wireguard");

    let ns = TestNamespace::new("netns-genl")?;
    let netns = Netns::open(ns.name())?;
    let wg: Connection<Wireguard> = netns.connection_async().await?;
    drop(wg);
    Ok(())
}

/// A connection made in a namespace knows it, and a sibling of another
/// protocol lands there too, however the first was opened (#520).
#[tokio::test]
async fn connections_know_their_namespace_and_siblings_follow() -> nlink::Result<()> {
    use nlink::netlink::Nftables;
    nlink::require_root!();

    let ns = TestNamespace::new("netns-sib")?;
    let netns = Netns::open(ns.name())?;
    let by_handle: Connection<Route> = netns.connection()?;
    let by_name: Connection<Route> = namespace::connection_for(ns.name())?;
    for conn in [&by_handle, &by_name] {
        assert_eq!(conn.netns()?.id(), netns.id());
        let nft = conn.sibling::<Nftables>()?;
        assert_eq!(nft.netns()?.id(), netns.id());
    }
    let host = Connection::<Route>::new()?;
    assert_eq!(host.netns()?.id(), Netns::current()?.id());
    Ok(())
}

/// A pool opens its namespace once. When the name is deleted and a new
/// namespace is created under it, a replacement connection is refused
/// rather than made in the new namespace, which it was before (#520).
#[tokio::test]
async fn a_pool_never_moves_to_a_namespace_recreated_under_its_name() -> nlink::Result<()> {
    use nlink::netlink::pool::ConnectionPoolBuilder;
    nlink::require_root!();

    let name = format!("nlk-pool-{}", std::process::id());
    let first = Netns::create(&name)?;
    let pool = ConnectionPoolBuilder::<Route>::new()
        .namespace(name.as_str())
        .size(1)
        .acquire_timeout(Duration::from_millis(300))
        .build()
        .await?;
    {
        let conn = pool.acquire().await?;
        assert_eq!(conn.netns()?.id(), first.id());
    }

    namespace::delete(&name)?;
    let second = Netns::create(&name)?;
    pool.acquire().await?.invalidate();
    tokio::time::sleep(Duration::from_millis(200)).await;
    match pool.acquire().await {
        Ok(conn) => panic!(
            "the pool replaced its connection with one in {}, the new namespace",
            conn.netns()?.id()
        ),
        Err(e) => assert!(e.is_timeout() || e.is_pool_exhausted(), "{e}"),
    }
    drop(first);
    second.delete()?;
    Ok(())
}

/// A watch stream started through a namespace's name ends with
/// `NamespaceDeleted` when the name is deleted (#504, #520).
#[tokio::test]
async fn a_watch_on_a_named_namespace_ends_when_it_is_deleted() -> nlink::Result<()> {
    use tokio_stream::StreamExt;
    nlink::require_root!();

    let name = format!("nlk-watch-{}", std::process::id());
    let netns = Netns::create(&name)?;
    let mut stream = nlink::facade::watch::route_changes_in_namespace(&name).await?;
    namespace::delete(&name)?;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(item) = stream.next().await {
            if let Err(e) = item {
                return Some(e);
            }
        }
        None
    })
    .await
    .expect("the stream should end within 10 s");
    let err = ended.expect("the stream should end with an error");
    assert!(err.is_namespace_deleted(), "{err}");
    drop(netns);
    Ok(())
}

/// `set_nsid` gives a namespace an id here, and `get_nsid` and
/// `get_nsid_for_pid` read it back (#669). All three padded their one-byte
/// `rtgenmsg` twice, so the attribute sat four bytes past where the kernel
/// looks, and every call failed: "Peer netns reference is missing"
/// (EINVAL).
#[tokio::test]
async fn nsids_are_set_and_read() -> nlink::Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    nlink::require_root!();

    let ns = TestNamespace::new("netns-nsid")?;
    let peer = TestNamespace::new("netns-nsid-peer")?;
    let conn = ns.connection()?;
    let netns = Netns::open(peer.name())?;
    let fd = netns.as_fd().as_raw_fd();
    // NETNSA_NSID_NOT_ASSIGNED, -1: no id yet.
    assert_eq!(conn.get_nsid(fd).await?, u32::MAX);
    conn.set_nsid(fd, 7).await?;
    assert_eq!(conn.get_nsid(fd).await?, 7);
    let listed = ns.exec("ip", &["netns", "list-id"])?;
    assert!(listed.contains("nsid 7 "), "{listed}");

    // A process inside the namespace: it enters before it execs.
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("10");
    let mut child = peer.spawn(cmd)?;
    let got = conn.get_nsid_for_pid(child.id()).await;
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(got?, 7);
    Ok(())
}

/// Deletes a named namespace, and its owner tag, when the test is done
/// with it, however it ends.
struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = namespace::delete(&self.0);
        let _ = namespace::remove_owner_tag(&self.0);
        let _ = std::fs::remove_file(format!("/var/run/netns/{}", self.0));
    }
}

/// `create_with` tags a namespace with its owner, `owner_of` and
/// `list_owned` read the tag, and `delete` removes it with the namespace
/// (#522).
#[tokio::test]
async fn an_owner_tag_goes_with_its_namespace() -> nlink::Result<()> {
    use namespace::CreateOptions;
    nlink::require_root!();

    let name = format!("nlink-owned-{}", std::process::id());
    let owner = format!("nlink-test-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());
    let netns = Netns::create_with(&name, CreateOptions::new().owner(&owner))?;
    assert_eq!(netns.name(), Some(name.as_str()));
    assert_eq!(namespace::owner_of(&name)?.as_deref(), Some(owner.as_str()));
    assert_eq!(namespace::list_owned(&owner)?, std::slice::from_ref(&name));
    assert!(namespace::list_owned("someone-else")?.iter().all(|n| *n != name));

    netns.delete()?;
    assert_eq!(namespace::owner_of(&name)?, None);
    assert!(namespace::list_owned(&owner)?.is_empty());
    Ok(())
}

/// A stale marker — a `/run/netns` file nothing is mounted on, left by a
/// crash — is reclaimed with `reclaim_stale`, where `create` refuses it; a
/// live namespace never is, and a create that fails leaves no tag (#522).
#[tokio::test]
async fn reclaim_stale_takes_a_dead_marker_and_never_a_live_namespace() -> nlink::Result<()> {
    use namespace::CreateOptions;
    nlink::require_root!();

    let name = format!("nlink-stale-{}", std::process::id());
    let _cleanup = Cleanup(name.clone());
    std::fs::create_dir_all("/var/run/netns")?;
    std::fs::write(format!("/var/run/netns/{name}"), b"")?;
    assert!(namespace::create(&name).expect_err("a marker is there").is_already_exists());

    namespace::create_with(&name, CreateOptions::new().reclaim_stale(true))?;
    assert!(namespace::is_namespace(&name));

    let err = namespace::create_with(&name, CreateOptions::new().reclaim_stale(true).owner("late"))
        .expect_err("a live namespace is not reclaimed");
    assert!(err.is_already_exists(), "{err}");
    assert!(namespace::is_namespace(&name));
    assert_eq!(namespace::owner_of(&name)?, None, "the failed create removed its tag");
    Ok(())
}

/// Removes `/etc/netns/<name>/` when the test is done with it.
struct EtcNetns(std::path::PathBuf);

impl EtcNetns {
    fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::path::PathBuf::from("/etc/netns").join(name);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for EtcNetns {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cat_hosts(cmd: namespace::NetnsCommand) -> nlink::Result<String> {
    let out = cmd.output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `/etc/netns` overlay as asked (#521): off gives the host's
/// `/etc/hosts`, strict and best effort the namespace's. A bind the kernel
/// refuses — here a directory over a file — fails a strict spawn and is
/// left out of a best-effort one. Where the environment refuses the
/// private mount namespace altogether, best effort runs with the host's.
#[tokio::test]
async fn an_etc_overlay_is_given_as_asked() -> nlink::Result<()> {
    use namespace::{NetnsCommand, Overlay};
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-overlay")?;
    let etc = EtcNetns::new(ns.name())?;
    std::fs::write(etc.0.join("hosts"), "10.9.9.9 overlaid\n")?;
    let cat = || {
        let mut c = Command::new("cat");
        c.arg("/etc/hosts");
        c
    };
    let run = |overlay| cat_hosts(NetnsCommand::new(ns.name(), cat())?.etc_overlay(overlay));
    assert!(!run(Overlay::Off)?.contains("overlaid"));
    if namespace::etc_overlay_supported() {
        assert!(run(Overlay::Strict)?.contains("overlaid"));
    } else {
        assert!(run(Overlay::Strict).is_err(), "the probe says strict cannot work here");
    }
    // Best effort runs either way, and gets the overlay wherever binds over
    // /etc are allowed — everywhere this suite runs.
    assert!(run(Overlay::BestEffort)?.contains("overlaid"));

    // A bind the kernel refuses: a directory over a file.
    std::fs::remove_file(etc.0.join("hosts"))?;
    std::fs::create_dir(etc.0.join("hosts"))?;
    assert!(run(Overlay::Strict).is_err(), "a strict overlay fails without its bind");
    assert!(!run(Overlay::BestEffort)?.contains("overlaid"));

    // Through a `Netns` opened by name, too.
    let netns = Netns::open(ns.name())?;
    let out = cat_hosts(netns.command(cat())?.etc_overlay(Overlay::Off))?;
    assert!(!out.is_empty());
    Ok(())
}

/// A process starts in its cgroup (#521): it joins before it enters the
/// namespace, so nothing it starts escapes the cgroup.
#[tokio::test]
async fn a_process_starts_in_its_cgroup() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    nlink::require_root!();
    // cgroupfs is the host's to write.
    nlink::require_host_root!();

    let ns = TestNamespace::new("cmd-cgroup")?;
    let name = format!("nlink-test-{}", std::process::id());
    let dir = std::path::PathBuf::from("/sys/fs/cgroup").join(&name);
    std::fs::create_dir(&dir)?;
    let mut cmd = Command::new("cat");
    cmd.arg("/proc/self/cgroup");
    let out = NetnsCommand::new(ns.name(), cmd)?.cgroup(&dir).output();
    let _ = std::fs::remove_dir(&dir);
    let out = String::from_utf8_lossy(&out?.stdout).into_owned();
    assert_eq!(out.trim(), format!("0::/{name}"));
    Ok(())
}

/// The parent-death signal reaches the process when the thread that
/// spawned it ends (#521).
#[test]
fn pdeathsig_ends_the_process_with_its_spawning_thread() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-pdeath")?;
    let name = ns.name().to_string();
    let mut child = std::thread::spawn(move || {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");
        NetnsCommand::new(&name, cmd)?.pdeathsig(libc::SIGKILL).spawn()
    })
    .join()
    .expect("the spawning thread")?;
    let started = std::time::Instant::now();
    let status = child.wait()?;
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    Ok(())
}

/// The parent pid of `pid`, from `/proc`.
fn ppid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok())
}

/// A detached process is no child of the caller's, runs in the namespace,
/// and with an exit-status file has its exit code written when it ends
/// (#521).
#[test]
fn a_detached_process_runs_in_the_namespace_and_reports_its_exit() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    use std::time::{Duration, Instant};
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-detached")?;
    let dir = std::env::temp_dir().join(format!("nlink-detached-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (netns_file, status_file) = (dir.join("netns"), dir.join("status"));
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(format!("readlink /proc/self/ns/net > {}; sleep 0.3; exit 7", netns_file.display()));
    let pid = NetnsCommand::new(ns.name(), cmd)?.exit_status_file(&status_file).spawn_detached()?;
    assert_ne!(ppid_of(pid), Some(std::process::id()), "not the caller's child");

    let started = Instant::now();
    while !status_file.exists() && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(std::fs::read_to_string(&status_file)?, "7\n");
    let inode = Netns::open(ns.name())?.id().ino();
    assert_eq!(std::fs::read_to_string(&netns_file)?.trim(), format!("net:[{inode}]"));

    // Without the file, the pid is the command's own; a start that fails
    // is an error here.
    let mut cmd = Command::new("sleep");
    cmd.arg("5");
    let pid = NetnsCommand::new(ns.name(), cmd)?.spawn_detached()?;
    assert!(std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?.starts_with("sleep"));
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let err = NetnsCommand::new(ns.name(), Command::new("/nonexistent/program"))?
        .spawn_detached()
        .expect_err("no such program");
    assert!(err.to_string().contains("No such file"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A namespace process as a tokio child (#521): spawned, waited on, and
/// its output collected without blocking the runtime.
#[tokio::test]
async fn a_tokio_child_runs_in_the_namespace() -> nlink::Result<()> {
    use namespace::NetnsCommand;
    use std::process::Command;
    nlink::require_root!();

    let ns = TestNamespace::new("cmd-tokio")?;
    let mut cmd = Command::new("readlink");
    cmd.arg("/proc/self/ns/net");
    let out = NetnsCommand::new(ns.name(), cmd)?.output_async().await?;
    let inode = Netns::open(ns.name())?.id().ino();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("net:[{inode}]"));
    let status = NetnsCommand::new(ns.name(), Command::new("true"))?.spawn_tokio()?.wait().await?;
    assert!(status.success());
    Ok(())
}
