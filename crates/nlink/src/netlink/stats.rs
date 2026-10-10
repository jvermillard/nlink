//! Statistics helpers for computing deltas and rates.
//!
//! This module provides utilities for tracking network statistics over time,
//! computing deltas between snapshots, and calculating rates.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::netlink::stats::{StatsSnapshot, StatsTracker};
//! use std::time::Duration;
//!
//! // Option 1: Manual rate calculation between snapshots
//! let links = conn.get_links().await?;
//! let snapshot1 = StatsSnapshot::from_links(&links);
//!
//! tokio::time::sleep(Duration::from_secs(1)).await;
//!
//! let links = conn.get_links().await?;
//! let snapshot2 = StatsSnapshot::from_links(&links);
//!
//! let rates = snapshot2.rates(&snapshot1, Duration::from_secs(1));
//! for (ifindex, link_rates) in &rates.links {
//!     println!("Interface {}: {:.2} Mbps RX, {:.2} Mbps TX",
//!         ifindex,
//!         link_rates.rx_bps() / 1_000_000.0,
//!         link_rates.tx_bps() / 1_000_000.0);
//! }
//!
//! // Option 2: Use StatsTracker for continuous monitoring
//! let mut tracker = StatsTracker::new();
//! loop {
//!     let links = conn.get_links().await?;
//!     let snapshot = StatsSnapshot::from_links(&links);
//!     if let Some(rates) = tracker.update(snapshot) {
//!         println!("Total: {:.2} Mbps", rates.total_bytes_per_sec() * 8.0 / 1_000_000.0);
//!     }
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, time::Duration};

use super::messages::{LinkMessage, TcMessage};

/// Statistics for a network interface.
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    /// Interface name.
    pub name: Option<String>,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Packets received.
    pub rx_packets: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Receive drops.
    pub rx_dropped: u64,
    /// Transmit drops.
    pub tx_dropped: u64,
    /// Multicast packets received.
    pub multicast: u64,
    /// Collisions.
    pub collisions: u64,
}

impl LinkStats {
    /// Create from a LinkMessage.
    pub fn from_link_message(msg: &LinkMessage) -> Self {
        if let Some(ref stats) = msg.stats {
            Self {
                name: msg.name.clone(),
                rx_bytes: stats.rx_bytes,
                tx_bytes: stats.tx_bytes,
                rx_packets: stats.rx_packets,
                tx_packets: stats.tx_packets,
                rx_errors: stats.rx_errors,
                tx_errors: stats.tx_errors,
                rx_dropped: stats.rx_dropped,
                tx_dropped: stats.tx_dropped,
                multicast: stats.multicast,
                collisions: stats.collisions,
            }
        } else {
            Self {
                name: msg.name.clone(),
                ..Default::default()
            }
        }
    }

    /// Total bytes (RX + TX).
    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    /// Total packets (RX + TX).
    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    /// Total errors (RX + TX).
    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }

    /// Total drops (RX + TX).
    pub fn total_dropped(&self) -> u64 {
        self.rx_dropped + self.tx_dropped
    }
}

/// Rate statistics for a network interface (per second).
#[derive(Debug, Clone, Default)]
pub struct LinkRates {
    /// Interface name.
    pub name: Option<String>,
    /// Bytes per second received.
    pub rx_bytes_per_sec: f64,
    /// Bytes per second transmitted.
    pub tx_bytes_per_sec: f64,
    /// Packets per second received.
    pub rx_packets_per_sec: f64,
    /// Packets per second transmitted.
    pub tx_packets_per_sec: f64,
    /// Receive errors per second.
    pub rx_errors_per_sec: f64,
    /// Transmit errors per second.
    pub tx_errors_per_sec: f64,
    /// Receive drops per second.
    pub rx_dropped_per_sec: f64,
    /// Transmit drops per second.
    pub tx_dropped_per_sec: f64,
}

impl LinkRates {
    /// The rates between two samples of one link, `elapsed` apart — what
    /// [`StatsSnapshot::rates`] computes per link, for a caller that keeps
    /// the previous sample itself.
    ///
    /// `None` when the samples cannot be compared: a different name at
    /// the ifindex (another link), a counter that went backwards (the link
    /// was recreated, or its counters reset), or no time between them. A
    /// decrease used to be taken for a 64-bit wrap, which never happens in
    /// practice, and reported about 1.8e19 bytes/s (#506).
    pub fn between(prev: &LinkStats, now: &LinkStats, elapsed: Duration) -> Option<Self> {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 || prev.name != now.name {
            return None;
        }
        let rate = |now: u64, prev: u64| Some(now.checked_sub(prev)? as f64 / secs);
        Some(Self {
            name: now.name.clone(),
            rx_bytes_per_sec: rate(now.rx_bytes, prev.rx_bytes)?,
            tx_bytes_per_sec: rate(now.tx_bytes, prev.tx_bytes)?,
            rx_packets_per_sec: rate(now.rx_packets, prev.rx_packets)?,
            tx_packets_per_sec: rate(now.tx_packets, prev.tx_packets)?,
            rx_errors_per_sec: rate(now.rx_errors, prev.rx_errors)?,
            tx_errors_per_sec: rate(now.tx_errors, prev.tx_errors)?,
            rx_dropped_per_sec: rate(now.rx_dropped, prev.rx_dropped)?,
            tx_dropped_per_sec: rate(now.tx_dropped, prev.tx_dropped)?,
        })
    }

    /// Total bytes per second (RX + TX).
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.rx_bytes_per_sec + self.tx_bytes_per_sec
    }

    /// Total packets per second (RX + TX).
    pub fn total_packets_per_sec(&self) -> f64 {
        self.rx_packets_per_sec + self.tx_packets_per_sec
    }

    /// RX bandwidth in bits per second.
    pub fn rx_bps(&self) -> f64 {
        self.rx_bytes_per_sec * 8.0
    }

    /// TX bandwidth in bits per second.
    pub fn tx_bps(&self) -> f64 {
        self.tx_bytes_per_sec * 8.0
    }

    /// Total bandwidth in bits per second.
    pub fn total_bps(&self) -> f64 {
        self.total_bytes_per_sec() * 8.0
    }
}

/// Statistics for a TC qdisc/class.
#[derive(Debug, Clone, Default)]
pub struct TcStats {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes transmitted.
    pub bytes: u64,
    /// Packets transmitted.
    pub packets: u64,
    /// Packets dropped.
    pub drops: u32,
    /// Packets overlimit.
    pub overlimits: u32,
    /// Packets requeued.
    pub requeues: u32,
    /// Current queue length.
    pub qlen: u32,
    /// Current backlog in bytes.
    pub backlog: u32,
}

impl TcStats {
    /// Create from a TcMessage.
    pub fn from_tc_message(msg: &TcMessage) -> Self {
        Self {
            kind: msg.kind.clone(),
            bytes: msg.bytes(),
            packets: msg.packets(),
            drops: msg.drops(),
            overlimits: msg.overlimits(),
            requeues: msg.requeues(),
            qlen: msg.qlen(),
            backlog: msg.backlog(),
        }
    }
}

/// Rate statistics for a TC qdisc/class (per second).
#[derive(Debug, Clone, Default)]
pub struct TcRates {
    /// Qdisc/class kind.
    pub kind: Option<String>,
    /// Bytes per second.
    pub bytes_per_sec: f64,
    /// Packets per second.
    pub packets_per_sec: f64,
    /// Drops per second.
    pub drops_per_sec: f64,
    /// Overlimits per second.
    pub overlimits_per_sec: f64,
    /// Requeues per second.
    pub requeues_per_sec: f64,
}

impl TcRates {
    /// The rates between two samples of one qdisc or class, `elapsed`
    /// apart; see [`LinkRates::between`].
    ///
    /// `None` when the kind changed (a qdisc replaced by another kind at
    /// the same handle) or bytes or packets went backwards (a recreate)
    /// (#506). Drops, overlimits and requeues are 32-bit in the kernel and
    /// do wrap, so with bytes and packets moving forward a decrease there
    /// is taken as one wrap.
    pub fn between(prev: &TcStats, now: &TcStats, elapsed: Duration) -> Option<Self> {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 || prev.kind != now.kind {
            return None;
        }
        let rate64 = |now: u64, prev: u64| Some(now.checked_sub(prev)? as f64 / secs);
        let rate32 = |now: u32, prev: u32| f64::from(now.wrapping_sub(prev)) / secs;
        Some(Self {
            kind: now.kind.clone(),
            bytes_per_sec: rate64(now.bytes, prev.bytes)?,
            packets_per_sec: rate64(now.packets, prev.packets)?,
            drops_per_sec: rate32(now.drops, prev.drops),
            overlimits_per_sec: rate32(now.overlimits, prev.overlimits),
            requeues_per_sec: rate32(now.requeues, prev.requeues),
        })
    }

    /// Bandwidth in bits per second.
    pub fn bps(&self) -> f64 {
        self.bytes_per_sec * 8.0
    }
}

/// A snapshot of network statistics at a point in time.
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    /// Link statistics by interface index.
    pub links: HashMap<u32, LinkStats>,
    /// Qdisc statistics by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcStats>,
    /// Class statistics by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcStats>,
}

impl StatsSnapshot {
    /// Create a new empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a snapshot from link messages.
    pub fn from_links(links: &[LinkMessage]) -> Self {
        let mut snapshot = Self::new();
        for link in links {
            let stats = LinkStats::from_link_message(link);
            snapshot.links.insert(link.ifindex(), stats);
        }
        snapshot
    }

    /// Create a snapshot from TC messages.
    pub fn from_tc(qdiscs: &[TcMessage], classes: &[TcMessage]) -> Self {
        let mut snapshot = Self::new();

        for qdisc in qdiscs {
            let stats = TcStats::from_tc_message(qdisc);
            snapshot
                .qdiscs
                .insert((qdisc.ifindex(), qdisc.handle_raw()), stats);
        }

        for class in classes {
            let stats = TcStats::from_tc_message(class);
            snapshot
                .classes
                .insert((class.ifindex(), class.handle_raw()), stats);
        }

        snapshot
    }

    /// Add link statistics to the snapshot.
    pub fn add_links(&mut self, links: &[LinkMessage]) {
        for link in links {
            let stats = LinkStats::from_link_message(link);
            self.links.insert(link.ifindex(), stats);
        }
    }

    /// Add qdisc statistics to the snapshot.
    pub fn add_qdiscs(&mut self, qdiscs: &[TcMessage]) {
        for qdisc in qdiscs {
            let stats = TcStats::from_tc_message(qdisc);
            self.qdiscs
                .insert((qdisc.ifindex(), qdisc.handle_raw()), stats);
        }
    }

    /// Add class statistics to the snapshot.
    pub fn add_classes(&mut self, classes: &[TcMessage]) {
        for class in classes {
            let stats = TcStats::from_tc_message(class);
            self.classes
                .insert((class.ifindex(), class.handle_raw()), stats);
        }
    }

    /// Compute rates between this snapshot and a previous one.
    ///
    /// Returns rate statistics for every interface and TC object that is
    /// in both snapshots and can be compared — see [`LinkRates::between`]
    /// and [`TcRates::between`]. One that was recreated, renamed or reset
    /// in between has no entry for this interval rather than a rate of
    /// about 1.8e19 (#506).
    pub fn rates(&self, previous: &StatsSnapshot, duration: Duration) -> RatesSnapshot {
        let mut rates = RatesSnapshot::new();
        for (ifindex, current) in &self.links {
            if let Some(rate) = previous
                .links
                .get(ifindex)
                .and_then(|prev| LinkRates::between(prev, current, duration))
            {
                rates.links.insert(*ifindex, rate);
            }
        }
        for (key, current) in &self.qdiscs {
            if let Some(rate) = previous
                .qdiscs
                .get(key)
                .and_then(|prev| TcRates::between(prev, current, duration))
            {
                rates.qdiscs.insert(*key, rate);
            }
        }
        for (key, current) in &self.classes {
            if let Some(rate) = previous
                .classes
                .get(key)
                .and_then(|prev| TcRates::between(prev, current, duration))
            {
                rates.classes.insert(*key, rate);
            }
        }
        rates
    }
}

/// A snapshot of rate statistics.
#[derive(Debug, Clone, Default)]
pub struct RatesSnapshot {
    /// Link rates by interface index.
    pub links: HashMap<u32, LinkRates>,
    /// Qdisc rates by (ifindex, handle).
    pub qdiscs: HashMap<(u32, u32), TcRates>,
    /// Class rates by (ifindex, handle).
    pub classes: HashMap<(u32, u32), TcRates>,
}

impl RatesSnapshot {
    /// Create a new empty rates snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total RX bytes per second across all interfaces.
    pub fn total_rx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.rx_bytes_per_sec).sum()
    }

    /// Get total TX bytes per second across all interfaces.
    pub fn total_tx_bytes_per_sec(&self) -> f64 {
        self.links.values().map(|r| r.tx_bytes_per_sec).sum()
    }

    /// Get total bytes per second across all interfaces.
    pub fn total_bytes_per_sec(&self) -> f64 {
        self.total_rx_bytes_per_sec() + self.total_tx_bytes_per_sec()
    }
}

/// Helper struct for tracking statistics over time.
///
/// This maintains the previous snapshot and computes rates automatically.
/// It also caches the most recent rates for convenient access.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use nlink::netlink::stats::StatsSnapshot;
/// # use std::time::Duration;
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use nlink::netlink::stats::StatsTracker;
///
/// let mut tracker = StatsTracker::new();
///
/// loop {
///     let links = conn.get_links().await?;
///     let snapshot = StatsSnapshot::from_links(&links);
///
///     // Update returns rates if we have a previous sample
///     if let Some(rates) = tracker.update(snapshot) {
///         for (ifindex, link_rates) in &rates.links {
///             println!("Interface {}: {:.2} Mbps", ifindex, link_rates.total_bps() / 1_000_000.0);
///         }
///     }
///
///     // Can also access cached rates later
///     if let Some(rate) = tracker.get_link_rate(1) {
///         println!("eth0: {:.2} Mbps RX", rate.rx_bps() / 1_000_000.0);
///     }
///
///     tokio::time::sleep(Duration::from_secs(1)).await;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct StatsTracker {
    previous: Option<StatsSnapshot>,
    previous_time: Option<std::time::Instant>,
    last_rates: Option<RatesSnapshot>,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsTracker {
    /// Create a new stats tracker.
    pub fn new() -> Self {
        Self {
            previous: None,
            previous_time: None,
            last_rates: None,
        }
    }

    /// Update with a new snapshot and return the rates since the last update.
    ///
    /// On the first call, returns `None` since there's no previous snapshot.
    /// The computed rates are cached and can be accessed via [`last_rates`](Self::last_rates),
    /// [`get_link_rate`](Self::get_link_rate), etc.
    pub fn update(&mut self, snapshot: StatsSnapshot) -> Option<RatesSnapshot> {
        let now = std::time::Instant::now();

        let rates = if let (Some(prev), Some(prev_time)) = (&self.previous, self.previous_time) {
            let duration = now.duration_since(prev_time);
            Some(snapshot.rates(prev, duration))
        } else {
            None
        };

        self.previous = Some(snapshot);
        self.previous_time = Some(now);
        self.last_rates = rates.clone();

        rates
    }

    /// Reset the tracker, clearing the previous snapshot and cached rates.
    pub fn reset(&mut self) {
        self.previous = None;
        self.previous_time = None;
        self.last_rates = None;
    }

    /// Get the previous snapshot, if any.
    pub fn previous(&self) -> Option<&StatsSnapshot> {
        self.previous.as_ref()
    }

    /// Get the last computed rates, if any.
    ///
    /// This returns the rates from the most recent [`update`](Self::update) call.
    /// Returns `None` if `update` has been called fewer than 2 times or after [`reset`](Self::reset).
    pub fn last_rates(&self) -> Option<&RatesSnapshot> {
        self.last_rates.as_ref()
    }

    /// Get the cached rate for a specific interface by index.
    ///
    /// Returns `None` if no rates are cached or if the interface wasn't in the last snapshot.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nlink::netlink::stats::StatsTracker;
    /// # let tracker = StatsTracker::new();
    /// # let ifindex = 2;
    /// if let Some(rate) = tracker.get_link_rate(ifindex) {
    ///     println!("RX: {:.2} Mbps, TX: {:.2} Mbps",
    ///         rate.rx_bps() / 1_000_000.0,
    ///         rate.tx_bps() / 1_000_000.0);
    /// }
    /// ```
    pub fn get_link_rate(&self, ifindex: u32) -> Option<&LinkRates> {
        self.last_rates.as_ref()?.links.get(&ifindex)
    }

    /// Get all cached link rates.
    ///
    /// Returns `None` if no rates are cached.
    pub fn get_all_link_rates(&self) -> Option<&HashMap<u32, LinkRates>> {
        self.last_rates.as_ref().map(|r| &r.links)
    }

    /// Get the cached rate for a specific qdisc.
    ///
    /// The key is (ifindex, handle).
    pub fn get_qdisc_rate(&self, ifindex: u32, handle: u32) -> Option<&TcRates> {
        self.last_rates.as_ref()?.qdiscs.get(&(ifindex, handle))
    }

    /// Get the cached rate for a specific class.
    ///
    /// The key is (ifindex, handle).
    pub fn get_class_rate(&self, ifindex: u32, handle: u32) -> Option<&TcRates> {
        self.last_rates.as_ref()?.classes.get(&(ifindex, handle))
    }

    /// Check if rates are available (i.e., update has been called at least twice).
    pub fn has_rates(&self) -> bool {
        self.last_rates.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(name: &str, rx_bytes: u64) -> LinkStats {
        LinkStats {
            name: Some(name.to_string()),
            rx_bytes,
            ..Default::default()
        }
    }

    fn tc(kind: &str, bytes: u64, drops: u32) -> TcStats {
        TcStats {
            kind: Some(kind.to_string()),
            bytes,
            packets: bytes / 100,
            drops,
            ..Default::default()
        }
    }

    /// #506: a counter that goes backwards is a reset — a recreated link,
    /// a replaced qdisc — not a 64-bit wrap. Taken for a wrap it reported
    /// about 1.8e19 bytes/s.
    #[test]
    fn a_counter_that_goes_backwards_is_a_reset_not_a_wrap() {
        let second = Duration::from_secs(1);
        let rates = LinkRates::between(&link("eth0", 1000), &link("eth0", 3000), second).unwrap();
        assert_eq!(rates.rx_bytes_per_sec, 2000.0);
        assert!(LinkRates::between(&link("eth0", 5000), &link("eth0", 10), second).is_none());

        let mut prev = StatsSnapshot::new();
        prev.links.insert(2, link("eth0", 5000));
        prev.qdiscs.insert((2, 0x10000), tc("htb", 9000, 0));
        let mut now = StatsSnapshot::new();
        now.links.insert(2, link("eth0", 10));
        now.qdiscs.insert((2, 0x10000), tc("htb", 100, 0));
        let rates = now.rates(&prev, second);
        assert!(rates.links.is_empty(), "{:?}", rates.links);
        assert!(rates.qdiscs.is_empty(), "{:?}", rates.qdiscs);
    }

    /// Another link at the ifindex, or another kind of qdisc at the
    /// handle, is not the object the previous sample was of.
    #[test]
    fn another_object_under_the_same_key_has_no_rate() {
        let second = Duration::from_secs(1);
        assert!(LinkRates::between(&link("eth0", 10), &link("eth1", 20), second).is_none());
        assert!(TcRates::between(&tc("htb", 10, 0), &tc("prio", 20, 0), second).is_none());
        assert!(LinkRates::between(&link("eth0", 10), &link("eth0", 20), Duration::ZERO).is_none());
    }

    /// The 32-bit queue counters do wrap; with bytes and packets moving
    /// forward, a smaller drop count is one wrap.
    #[test]
    fn a_32_bit_drop_counter_wraps() {
        let rates = TcRates::between(
            &tc("htb", 1000, u32::MAX - 9),
            &tc("htb", 2000, 10),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(rates.drops_per_sec, 20.0);
        assert_eq!(rates.bytes_per_sec, 1000.0);
    }

    #[test]
    fn test_link_stats_totals() {
        let stats = LinkStats {
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 1,
            tx_errors: 2,
            rx_dropped: 3,
            tx_dropped: 4,
            ..Default::default()
        };

        assert_eq!(stats.total_bytes(), 3000);
        assert_eq!(stats.total_packets(), 30);
        assert_eq!(stats.total_errors(), 3);
        assert_eq!(stats.total_dropped(), 7);
    }

    #[test]
    fn test_link_rates_bps() {
        let rates = LinkRates {
            rx_bytes_per_sec: 1000.0,
            tx_bytes_per_sec: 2000.0,
            ..Default::default()
        };

        assert_eq!(rates.rx_bps(), 8000.0);
        assert_eq!(rates.tx_bps(), 16000.0);
        assert_eq!(rates.total_bps(), 24000.0);
    }

    #[test]
    fn test_stats_snapshot_rates() {
        let mut prev = StatsSnapshot::new();
        prev.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 1000,
                tx_bytes: 2000,
                ..Default::default()
            },
        );

        let mut curr = StatsSnapshot::new();
        curr.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 2000,
                tx_bytes: 4000,
                ..Default::default()
            },
        );

        let rates = curr.rates(&prev, Duration::from_secs(1));

        let link_rates = rates.links.get(&1).unwrap();
        assert_eq!(link_rates.rx_bytes_per_sec, 1000.0);
        assert_eq!(link_rates.tx_bytes_per_sec, 2000.0);
    }

    #[test]
    fn test_stats_tracker_caching() {
        let mut tracker = StatsTracker::new();

        // First update - no rates yet
        let mut snapshot1 = StatsSnapshot::new();
        snapshot1.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 1000,
                tx_bytes: 2000,
                ..Default::default()
            },
        );

        assert!(tracker.update(snapshot1).is_none());
        assert!(!tracker.has_rates());
        assert!(tracker.last_rates().is_none());
        assert!(tracker.get_link_rate(1).is_none());

        // Second update - now we have rates
        let mut snapshot2 = StatsSnapshot::new();
        snapshot2.links.insert(
            1,
            LinkStats {
                name: Some("eth0".to_string()),
                rx_bytes: 2000,
                tx_bytes: 4000,
                ..Default::default()
            },
        );

        let rates = tracker.update(snapshot2);
        assert!(rates.is_some());
        assert!(tracker.has_rates());

        // Check cached rates
        let cached = tracker.last_rates().unwrap();
        assert_eq!(cached.links.len(), 1);

        let link_rate = tracker.get_link_rate(1);
        assert!(link_rate.is_some());

        // Check that get_all_link_rates works
        let all_rates = tracker.get_all_link_rates().unwrap();
        assert_eq!(all_rates.len(), 1);
        assert!(all_rates.contains_key(&1));

        // Non-existent interface returns None
        assert!(tracker.get_link_rate(999).is_none());
    }

    #[test]
    fn test_stats_tracker_reset_clears_cache() {
        let mut tracker = StatsTracker::new();

        // Build up some state
        let mut snapshot1 = StatsSnapshot::new();
        snapshot1.links.insert(1, LinkStats::default());
        tracker.update(snapshot1);

        let mut snapshot2 = StatsSnapshot::new();
        snapshot2.links.insert(1, LinkStats::default());
        tracker.update(snapshot2);

        assert!(tracker.has_rates());

        // Reset should clear everything
        tracker.reset();
        assert!(!tracker.has_rates());
        assert!(tracker.last_rates().is_none());
        assert!(tracker.previous().is_none());
    }
}
