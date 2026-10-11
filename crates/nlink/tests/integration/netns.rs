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
