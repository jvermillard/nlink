//! ENOBUFS-resilient rtnetlink event watching.
//!
//! RTNETLINK twin of `nlink::netlink::nftables::resync` (Plan
//! 185). Same shape, different protocol: subscribe to multicast
//! groups + transparently re-dump state when the kernel drops
//! events under pressure (`-ENOBUFS`).
//!
//! Mirrors how `kube_rs::watcher(api, cfg) -> Stream` works —
//! `watcher`-style fanout has proven the right primitive for
//! long-lived self-resyncing watchers. Plan 191.
//!
//! # Example — owned, spawn-friendly
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent, ResyncMarker};
//! use nlink::NetworkEvent;
//! use tokio_stream::StreamExt;
//!
//! let factory: ConnectionFactory<Route> = Arc::new(|| Box::pin(async {
//!     Connection::<Route>::new()
//! }));
//!
//! let conn = Connection::<Route>::new()?;
//! let mut events = conn.into_events_with_resync(factory).await?;
//!
//! while let Some(item) = events.next().await {
//!     match item? {
//!         ResyncedEvent::Event(NetworkEvent::NewLink(l)) => {
//!             println!("+l {:?}", l.name());
//!         }
//!         ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
//!             println!("== resync start ==");
//!         }
//!         ResyncedEvent::Resynced(ev) => {
//!             println!("?? snapshot: {ev:?}");
//!         }
//!         ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
//!             println!("== resync end ==");
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;

use tokio_stream::Stream;

use super::events::NetworkEvent;
use crate::netlink::protocol::Route;
use crate::netlink::resync::{Backoff, ConnectionFactory, ResyncStream, ResyncedEvent, events_with_resync};
use crate::netlink::stream::{EventSubscription, OwnedEventStream};
use crate::{Connection, Result};

/// Walk the current rtnetlink state and return one `NewX(...)` event per
/// existing entity. Used internally by
/// [`Connection::<Route>::into_events_with_resync`] for ENOBUFS recovery
/// and the initial sync; exposed publicly so callers wiring their own
/// resync can re-use it. Plan 191 §2.5.
///
/// It covers what [`subscribe_all`](Connection::subscribe_all) joins and
/// the kernel can dump: links → netconf → addresses → nexthops → routes →
/// rules → neighbours → qdiscs → classes → filters → bridge MDB. It used to stop
/// at neighbours, so a mirror of qdiscs, rules or nexthops was emptied by
/// its first overflow and stayed empty (#503). Nexthops come before the
/// routes that use them. Network-namespace ids are subscribed to but have
/// no dump, so they are not here.
pub async fn rtnetlink_snapshot(conn: &Connection<Route>) -> Result<Vec<NetworkEvent>> {
    let mut out = Vec::new();

    let links = conn.get_links().await?;
    let bridges: Vec<u32> = links
        .iter()
        .filter(|l| l.kind() == Some("bridge"))
        .map(|l| l.ifindex())
        .collect();
    out.extend(links.into_iter().map(NetworkEvent::NewLink));
    // Each family's netconf (#523); a kernel without IPv6 has none of it.
    for family in [crate::AddressFamily::v4(), crate::AddressFamily::v6()] {
        match conn.get_netconf(family).await {
            Ok(nc) => out.extend(nc.into_iter().map(NetworkEvent::NewNetconf)),
            Err(e) if e.is_not_supported() || e.is_invalid_argument() => {}
            Err(e) => return Err(e),
        }
    }
    out.extend(
        conn.get_addresses()
            .await?
            .into_iter()
            .map(NetworkEvent::NewAddress),
    );
    // A kernel without nexthop objects says so; that is an empty dump.
    match conn.get_nexthops().await {
        Ok(nhs) => out.extend(nhs.into_iter().map(NetworkEvent::NewNexthop)),
        Err(e) if e.is_not_supported() || e.is_invalid_argument() => {}
        Err(e) => return Err(e),
    }
    out.extend(
        conn.get_routes()
            .await?
            .into_iter()
            .map(NetworkEvent::NewRoute),
    );
    out.extend(
        conn.get_rules()
            .await?
            .into_iter()
            .map(NetworkEvent::NewRule),
    );
    out.extend(
        conn.get_neighbors()
            .await?
            .into_iter()
            .map(NetworkEvent::NewNeighbor),
    );
    out.extend(
        conn.get_qdiscs()
            .await?
            .into_iter()
            .map(NetworkEvent::NewQdisc),
    );
    out.extend(
        conn.get_classes()
            .await?
            .into_iter()
            .map(NetworkEvent::NewClass),
    );
    out.extend(
        conn.get_filters()
            .await?
            .into_iter()
            .map(NetworkEvent::NewFilter),
    );
    for bridge in bridges {
        out.extend(
            conn.get_mdb_by_index(bridge)
                .await?
                .into_iter()
                .map(NetworkEvent::NewMdb),
        );
    }

    Ok(out)
}

/// Boxed snapshot future — what the resync closure produces.
type SnapshotFuture =
    Pin<Box<dyn Future<Output = Result<Vec<NetworkEvent>>> + Send + 'static>>;

/// Boxed snapshot closure — what `events_with_resync` consumes.
type SnapshotFn = Box<dyn FnMut() -> SnapshotFuture + Send + Unpin + 'static>;

/// Build the resync closure passed to [`events_with_resync`].
/// Each invocation opens a fresh `Connection<Route>` via the
/// factory + walks the kernel state via [`rtnetlink_snapshot`].
fn make_snapshot_fn(factory: ConnectionFactory<Route>) -> SnapshotFn {
    Box::new(move || {
        let factory = factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            rtnetlink_snapshot(&conn).await
        }) as SnapshotFuture
    })
}

/// Resync-wrapped `OwnedEventStream<Route>`. Returned by
/// [`Connection::<Route>::into_events_with_resync`]. `'static`
/// + `Send` — spawn-friendly with `tokio::spawn`.
pub type OwnedResyncStream =
    ResyncStream<'static, OwnedEventStream<Route>, NetworkEvent, SnapshotFn>;

/// Resync-wrapped `EventSubscription<'a, Route>`. Returned by
/// [`Connection::<Route>::subscribe_all_with_resync`].
/// Borrows the connection for `'a`.
pub type BorrowedResyncStream<'a> =
    ResyncStream<'static, EventSubscription<'a, Route>, NetworkEvent, SnapshotFn>;

impl Connection<Route> {
    /// Subscribe to every rtnetlink multicast group + return an
    /// ENOBUFS-resilient event stream that **owns** the
    /// connection.
    ///
    /// Mirrors [`Connection::<Nftables>::into_events_with_resync`]
    /// (Plan 185). The factory is invoked on every ENOBUFS
    /// overflow; the wrapper re-dumps state via
    /// [`rtnetlink_snapshot`] on a fresh connection and emits
    /// the snapshot items between
    /// [`ResyncMarker::ResyncStart`](crate::netlink::resync::ResyncMarker::ResyncStart)
    /// and [`ResyncMarker::ResyncEnd`](crate::netlink::resync::ResyncMarker::ResyncEnd)
    /// markers.
    ///
    /// **Important** — the fresh connection MUST be on the same
    /// netns. Use
    /// [`namespace::connection_for`](crate::netlink::namespace::connection_for)
    /// inside the factory for namespace-aware code; in the host
    /// netns plain `Connection::<Route>::new()` is fine.
    ///
    /// Subscribes to every rtnetlink multicast group before
    /// returning. Use [`Self::subscribe_all_with_resync`] if you
    /// need to retain borrowed access to the connection.
    ///
    /// Plan 191 §2.6.
    /// 0.19 Finding B — now `async` to acquire the request lock
    /// via the underlying `into_events().await`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn into_events_with_resync(
        self,
        factory: ConnectionFactory<Route>,
    ) -> Result<OwnedResyncStream> {
        self.subscribe_all()?;
        let stream = self.into_events().await;
        Ok(events_with_resync(stream, make_snapshot_fn(factory)).initial_snapshot(true))
    }

    /// Same as [`Self::into_events_with_resync`] but borrows the
    /// connection, which is yours again once the stream is dropped.
    ///
    /// While the stream is alive the connection serves requests only in
    /// dispatcher mode ([`Connection::with_dispatcher`]). In the default
    /// mutex mode the stream holds its request lock, and a request fails
    /// at once with [`Error::EventStreamActive`](crate::Error::EventStreamActive)
    /// (#505). The snapshot itself never uses this connection: it runs on
    /// one from the factory.
    ///
    /// Returns a stream that holds `&self` for `'a`. If you need
    /// to spawn the stream onto a tokio task, prefer
    /// [`Self::into_events_with_resync`] (the owned form is
    /// `'static + Send`).
    ///
    /// Plan 191 §2.6. 0.19 Finding A — `&self` (was `&mut self`).
    /// 0.19 Finding B — now `async`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn subscribe_all_with_resync(
        &self,
        factory: ConnectionFactory<Route>,
    ) -> Result<BorrowedResyncStream<'_>> {
        self.subscribe_all()?;
        let stream = self.events().await;
        Ok(events_with_resync(stream, make_snapshot_fn(factory)).initial_snapshot(true))
    }
}

impl Connection<Route> {
    /// An event stream that does not end (#523): every rtnetlink group,
    /// resynced after an overflow as
    /// [`into_events_with_resync`](Self::into_events_with_resync) is, on
    /// a connection from `factory` — and when that stream ends or fails,
    /// the error is yielded and a new one is made after `backoff`.
    ///
    /// Each run begins with an initial snapshot
    /// ([`ResyncMarker::InitialSyncStart`](crate::netlink::resync::ResyncMarker::InitialSyncStart)),
    /// so a mirror rebuilds itself after a restart. A namespace deleted
    /// under it, or one the factory cannot find, ends the stream: no
    /// restart can bring it back. So does [`Backoff::max_attempts`]
    /// restarts in a row without an event.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use std::sync::Arc;
    /// use nlink::netlink::{Connection, Route};
    /// use nlink::netlink::resync::{Backoff, ConnectionFactory};
    /// use tokio_stream::StreamExt;
    ///
    /// let factory: ConnectionFactory<Route> =
    ///     Arc::new(|| Box::pin(async { nlink::netlink::namespace::connection_for("lab-r1") }));
    /// let mut events = Connection::<Route>::events_restarting(factory, Backoff::default());
    /// while let Some(item) = events.next().await {
    ///     match item {
    ///         Ok(event) => println!("{event:?}"),
    ///         // Reported, and the stream goes on.
    ///         Err(e) => eprintln!("watch restarting: {e}"),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn events_restarting(factory: ConnectionFactory<Route>, backoff: Backoff) -> RestartingStream {
        let mut stream = RestartingStream {
            factory,
            backoff,
            state: RestartState::Done,
            attempts: 0,
        };
        stream.state = RestartState::Starting(stream.start());
        stream
    }
}

type StartFuture = Pin<Box<dyn Future<Output = Result<OwnedResyncStream>> + Send>>;

enum RestartState {
    Starting(StartFuture),
    Running(Pin<Box<OwnedResyncStream>>),
    Waiting(Pin<Box<tokio::time::Sleep>>),
    Done,
}

/// The stream of [`Connection::events_restarting`] (#523).
pub struct RestartingStream {
    factory: ConnectionFactory<Route>,
    backoff: Backoff,
    state: RestartState,
    /// Restarts since an event was last delivered.
    attempts: u32,
}

impl RestartingStream {
    fn start(&self) -> StartFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let conn = (factory)().await?;
            conn.into_events_with_resync(factory).await
        })
    }

    /// After a failure: wait and start again, or end.
    fn restart_or_end(&mut self, e: &crate::Error) {
        self.attempts += 1;
        let gone = e.is_namespace_deleted() || matches!(e, crate::Error::NamespaceNotFound { .. });
        let spent = self.backoff.max_attempts.is_some_and(|max| self.attempts > max);
        self.state = if gone || spent {
            tracing::info!(error = %e, "restarting event stream: giving up");
            RestartState::Done
        } else {
            let delay = self.backoff.delay(self.attempts);
            tracing::warn!(error = %e, ?delay, attempt = self.attempts, "restarting event stream");
            RestartState::Waiting(Box::pin(tokio::time::sleep(delay)))
        };
    }
}

impl Stream for RestartingStream {
    type Item = Result<ResyncedEvent<NetworkEvent>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match &mut this.state {
                RestartState::Done => return Poll::Ready(None),
                RestartState::Waiting(sleep) => {
                    if sleep.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    this.state = RestartState::Starting(this.start());
                }
                RestartState::Starting(fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(stream)) => this.state = RestartState::Running(Box::pin(stream)),
                    Poll::Ready(Err(e)) => {
                        this.restart_or_end(&e);
                        return Poll::Ready(Some(Err(e)));
                    }
                },
                RestartState::Running(stream) => match stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(item))) => {
                        if matches!(item, ResyncedEvent::Event(_)) {
                            this.attempts = 0;
                        }
                        return Poll::Ready(Some(Ok(item)));
                    }
                    Poll::Ready(Some(Err(e))) => {
                        this.restart_or_end(&e);
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(None) => {
                        let e = crate::Error::InvalidMessage("the event stream ended".into());
                        this.restart_or_end(&e);
                    }
                },
            }
        }
    }
}

// Anchor `Stream`-trait users without leaking `tokio_stream` —
// `ResyncStream` implements `Stream`; `OwnedResyncStream` /
// `BorrowedResyncStream` inherit it through the alias.
#[allow(dead_code)]
fn _streams_are_streams() {
    fn assert_stream<S: Stream + ?Sized>() {}
    assert_stream::<OwnedResyncStream>();
    assert_stream::<BorrowedResyncStream<'static>>();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::netlink::resync::ConnectionFuture;

    #[test]
    fn factory_is_clone_and_send() {
        let factory: ConnectionFactory<Route> = Arc::new(|| {
            Box::pin(async { Connection::<Route>::new() })
                as Pin<Box<dyn Future<Output = Result<Connection<Route>>> + Send + 'static>>
        });
        let _f2 = factory.clone();
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_send<T: Send>() {}
        assert_send_sync::<ConnectionFactory<Route>>();
        assert_send::<ConnectionFuture<Route>>();
    }

    #[test]
    fn snapshot_fn_is_send() {
        let factory: ConnectionFactory<Route> = Arc::new(|| {
            Box::pin(async { Connection::<Route>::new() })
        });
        // Make sure the snapshot-fn type bound is what
        // events_with_resync needs. Cannot exercise without a
        // socket; this is purely a compile-time check.
        let _fn = make_snapshot_fn(factory);
    }

    #[test]
    fn restarting_stream_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RestartingStream>();
    }

    /// A factory that never succeeds: an error per attempt, the waits
    /// growing, then the end after `max_attempts` restarts.
    #[tokio::test]
    async fn a_restarting_stream_gives_up_after_max_attempts() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::time::Duration;
        use tokio_stream::StreamExt;

        let calls = Arc::new(AtomicU32::new(0));
        let counted = calls.clone();
        let factory: ConnectionFactory<Route> = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(crate::Error::InvalidMessage("not yet".into())) })
        });
        let backoff = Backoff::new(Duration::from_millis(5), Duration::from_millis(20)).max_attempts(2);
        let mut stream = Connection::<Route>::events_restarting(factory, backoff);
        let mut errors = 0;
        while let Some(item) = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the stream ends")
        {
            assert!(item.is_err(), "{item:?}");
            errors += 1;
        }
        assert_eq!(errors, 3, "the first attempt and two restarts");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
