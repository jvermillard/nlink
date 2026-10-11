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
