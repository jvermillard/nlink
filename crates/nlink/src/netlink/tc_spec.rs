//! One qdisc spec for both paths (#515).
//!
//! [`QdiscSpec`] holds the imperative configs themselves — a netem is a
//! [`NetemConfig`], a TBF a [`TbfConfig`] — so the declarative
//! [`NetworkConfig`](crate::netlink::config::NetworkConfig) and the
//! imperative `Connection` take the same type, with the same defaults and
//! the same bugs fixed once. Before 0.32 the declarative side had its own
//! `DeclaredQdiscType`, with its own field types, a lowering per kind, and
//! its own comparison, and fixes reached one side or the other (#361 fixed
//! fq_codel's `flows` on one).
//!
//! A spec installs like any config (`conn.add_qdisc(dev, spec)`), says
//! whether a live qdisc already is it ([`QdiscSpec::matches`]), and checks
//! itself without a kernel ([`QdiscSpec::validate`]). With the `serde`
//! feature it reads and writes in the units tc(8) writes: `"10ms"`,
//! `"100mbit"`, `"1.5%"`, `"32kib"`.

use std::time::Duration;

use super::{
    builder::MessageBuilder,
    error::{Error, Result},
    messages::TcMessage,
    psched,
    tc::{
        ClsactConfig, FqCodelConfig, HtbQdiscConfig, InPlace, IngressConfig, NetemConfig,
        PrioConfig, QdiscConfig, SfqConfig, TbfConfig,
    },
    tc_handle::TcHandle,
};

/// A qdisc, for the declarative and the imperative path alike (#515).
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// use std::time::Duration;
/// use nlink::netlink::{config::NetworkConfig, tc::NetemConfig, tc_spec::QdiscSpec};
///
/// let spec = QdiscSpec::from(NetemConfig::new().delay(Duration::from_millis(10)).seed(7));
/// conn.replace_qdisc("eth0", spec.clone()).await?;
/// let config = NetworkConfig::new().qdisc("eth0", |q| q.spec(spec));
/// # let _ = config;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum QdiscSpec {
    /// netem.
    Netem(NetemConfig),
    /// HTB.
    Htb(HtbQdiscConfig),
    /// fq_codel.
    FqCodel(FqCodelConfig),
    /// TBF.
    Tbf(TbfConfig),
    /// sfq.
    Sfq(SfqConfig),
    /// prio.
    Prio(PrioConfig),
    /// The ingress hook.
    Ingress,
    /// The clsact hooks.
    Clsact,
    /// The kernel's own root qdisc: declared, the installed root is
    /// deleted and the kernel puts its default back (#514). Not something
    /// to install.
    KernelDefault,
}

macro_rules! from_config {
    ($($cfg:ident => $variant:ident),*) => {$(
        impl From<$cfg> for QdiscSpec {
            fn from(cfg: $cfg) -> Self {
                Self::$variant(cfg)
            }
        }
    )*};
}
from_config!(
    NetemConfig => Netem,
    HtbQdiscConfig => Htb,
    FqCodelConfig => FqCodel,
    TbfConfig => Tbf,
    SfqConfig => Sfq,
    PrioConfig => Prio
);

/// fq_codel's smallest quantum: `fq_codel_change()` stores
/// `max(256, quantum)`.
const FQ_CODEL_MIN_QUANTUM: u32 = 256;

/// The largest limit sfq keeps when neither depth nor flows is set, which
/// nlink never does: `sfq_change()` caps `limit` at `maxdepth * maxflows`,
/// `SFQ_MAX_DEPTH` (127) times `SFQ_DEFAULT_FLOWS` (128) by default.
const SFQ_MAX_LIMIT: u32 = 127 * 128;

impl QdiscSpec {
    /// The config to install, or `None` for the kernel default.
    fn config(&self) -> Option<&dyn QdiscConfig> {
        match self {
            Self::Netem(c) => Some(c),
            Self::Htb(c) => Some(c),
            Self::FqCodel(c) => Some(c),
            Self::Tbf(c) => Some(c),
            Self::Sfq(c) => Some(c),
            Self::Prio(c) => Some(c),
            Self::Ingress => Some(&IngressConfig),
            Self::Clsact => Some(&ClsactConfig),
            Self::KernelDefault => None,
        }
    }

    /// The kind: `"netem"`, `"htb"`, …, and `"default"` for the kernel's
    /// default.
    pub fn kind(&self) -> &'static str {
        self.config().map_or("default", |c| c.kind())
    }

    /// Whether `live` already is this qdisc: the same kind, with every
    /// parameter the spec sets as the kernel keeps it.
    ///
    /// The comparison is in the kernel's own units and quantisation:
    /// probabilities as 32-bit fractions, codel times in 1.024 µs units (a
    /// 20 ms target reads back as 19999 µs), TBF buckets as the transmission
    /// time the kernel stores. A kind that has no parser here compares the
    /// options' bytes, which errs towards "differs". The kernel's default
    /// matches a root with handle 0, which is what the kernel installs.
    pub fn matches(&self, live: &TcMessage) -> bool {
        use crate::netlink::{
            tc_options::QdiscOptions,
            tc_recipe_internals::{codel_round_trip_us, netem_matches},
        };

        if let Self::KernelDefault = self {
            return live.handle().as_raw() == 0;
        }
        if live.kind() != Some(self.kind()) {
            return false;
        }
        match (self, live.options()) {
            (Self::Netem(cfg), _) => netem_matches(cfg, live),
            (Self::Tbf(cfg), Some(QdiscOptions::Tbf(live))) => {
                // Rate, peakrate and limit come back exact. Burst and mtu
                // do not: the kernel keeps both buckets as nanoseconds and
                // reports them only as psched ticks, so the bytes read back
                // are a tick round trip of what was sent (32768 at 10 gbit
                // reads as 32719); compare against the same trip. The mtu
                // goes as TCA_TBF_PBURST only with a peak rate; otherwise
                // the kernel keeps the tick count written into `qopt.mtu`.
                let rate = cfg.rate.as_bytes_per_sec();
                let peak = cfg.peakrate.map(|r| r.as_bytes_per_sec());
                let burst = psched::tbf_bucket_round_trip(rate, cfg.burst.as_u32_saturating());
                let mtu = match peak {
                    Some(peak) => psched::tbf_bucket_round_trip(peak, cfg.mtu),
                    None => psched::tc_calc_xmitsize(rate, psched::tc_calc_xmittime(rate, cfg.mtu)),
                };
                // Without a limit there is no match, so an apply gets to
                // refuse the spec (`TbfConfig::write_options`) even where
                // an older apply installed it: the kernel's limit-0 TBF has
                // no queue and drops everything.
                cfg.limit.as_u32_saturating() != 0
                    && live.rate == rate
                    && live.burst == burst
                    && live.limit == cfg.limit.as_u32_saturating()
                    && live.peakrate == peak.unwrap_or(0)
                    && live.mtu == mtu
            }
            (Self::Htb(cfg), Some(QdiscOptions::Htb(live))) => {
                live.default_class == cfg.default_class
                    && live.rate2quantum == cfg.r2q
                    && cfg.direct_qlen.is_none_or(|q| live.direct_qlen == Some(q))
            }
            (Self::FqCodel(cfg), Some(QdiscOptions::FqCodel(live))) => {
                // Only what the spec sets is written; the kernel chooses
                // the rest. `quantum` is kept as `max(256, quantum)`.
                let us = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
                cfg.limit.is_none_or(|l| live.limit == l)
                    && cfg.flows.is_none_or(|f| live.flows == f)
                    && cfg
                        .target
                        .is_none_or(|t| codel_round_trip_us(us(t)) == live.target_us)
                    && cfg
                        .interval
                        .is_none_or(|i| codel_round_trip_us(us(i)) == live.interval_us)
                    && cfg
                        .quantum
                        .is_none_or(|q| live.quantum == q.max(FQ_CODEL_MIN_QUANTUM))
                    && cfg.ecn.is_none_or(|e| live.ecn == e)
                    && cfg
                        .ce_threshold
                        .is_none_or(|t| live.ce_threshold_us == Some(codel_round_trip_us(us(t))))
                    && cfg
                        .memory_limit
                        .is_none_or(|m| live.memory_limit == Some(m))
            }
            (Self::Sfq(cfg), Some(QdiscOptions::Sfq(live))) => {
                // A limit or quantum of 0 leaves the kernel its default, so
                // is not compared; the perturbation period always is, 0
                // being the kernel's "off". The limit is capped at
                // `maxdepth * maxflows`.
                live.perturb_period == cfg.perturb
                    && (cfg.limit == 0 || live.limit == cfg.limit.min(SFQ_MAX_LIMIT))
                    && (cfg.quantum == 0 || live.quantum == cfg.quantum)
            }
            (Self::Prio(cfg), Some(QdiscOptions::Prio(live))) => {
                live.bands == cfg.bands && live.priomap == cfg.effective_priomap()
            }
            (Self::Ingress | Self::Clsact, _) => true,
            // No parser for this kind, or no options reported: compare the
            // bytes, which errs towards "differs".
            _ => self
                .options_bytes()
                .is_some_and(|b| b.as_slice() == live.raw_options().unwrap_or(&[])),
        }
    }

    /// The `TCA_OPTIONS` payload, when the spec writes one.
    fn options_bytes(&self) -> Option<Vec<u8>> {
        let cfg = self.config()?;
        let mut builder = MessageBuilder::new(0, 0);
        let start = builder.len();
        cfg.write_options(&mut builder).ok()?;
        Some(builder.as_bytes()[start..].to_vec())
    }

    /// Check the spec without a kernel: what installing it would refuse
    /// before sending anything (a netem distribution with no jitter, a TBF
    /// without a limit, a loss model beside random loss, …).
    pub fn validate(&self) -> Result<()> {
        match self.config() {
            Some(cfg) => {
                let mut scratch = MessageBuilder::new(0, 0);
                cfg.write_options(&mut scratch)
            }
            None => Ok(()),
        }
    }

    /// Whether the kind has classes, and so `1:` as its default handle.
    pub fn is_classful(&self) -> bool {
        self.default_handle().is_some()
    }
}

impl QdiscConfig for QdiscSpec {
    fn kind(&self) -> &'static str {
        QdiscSpec::kind(self)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        match self.config() {
            Some(cfg) => cfg.write_options(builder),
            None => Err(Error::invalid_message(
                "the kernel's default qdisc is not installed: delete the root qdisc, and the \
                 kernel puts it back"
                    ,
            )),
        }
    }

    fn has_options(&self) -> bool {
        self.config().is_some_and(|c| c.has_options())
    }

    fn default_handle(&self) -> Option<TcHandle> {
        self.config().and_then(|c| c.default_handle())
    }

    fn in_place(&self, live: &TcMessage) -> InPlace {
        self.config().map_or(InPlace::Change, |c| c.in_place(live))
    }

    fn write_change_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        match self.config() {
            Some(cfg) => cfg.write_change_options(builder),
            None => self.write_options(builder),
        }
    }

    fn fixed_parent(&self) -> Option<TcHandle> {
        self.config().and_then(|c| c.fixed_parent())
    }
}

#[cfg(feature = "serde")]
mod serde_impl;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{Bytes, Percent, Rate};

    /// A live qdisc as a dump would report it: kind + raw `TCA_OPTIONS`.
    fn live(kind: &str, options: Option<Vec<u8>>) -> TcMessage {
        TcMessage {
            kind: Some(kind.to_string()),
            options,
            ..TcMessage::default()
        }
    }

    /// One native-endian `u32` attribute, the way the kernel writes it.
    fn attr_u32(attr_type: u16, value: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&8u16.to_ne_bytes());
        out.extend_from_slice(&attr_type.to_ne_bytes());
        out.extend_from_slice(&value.to_ne_bytes());
        out
    }

    fn bytes(spec: &QdiscSpec) -> Vec<u8> {
        spec.options_bytes().unwrap_or_default()
    }

    fn netem(delay_ms: u64) -> QdiscSpec {
        NetemConfig::new()
            .delay(Duration::from_millis(delay_ms))
            .jitter(Duration::from_millis(10))
            .loss(Percent::new(0.5))
            .reorder(Percent::new(3.0))
            .reorder_correlation(Percent::new(50.0))
            .rate(Rate::mbit(100))
            .gap(5)
            .into()
    }

    #[test]
    fn options_differ_when_a_parameter_does() {
        let htb = |class| QdiscSpec::from(HtbQdiscConfig::new().default_class(class));
        assert_ne!(bytes(&htb(0x10)), bytes(&htb(0x20)));
        assert_eq!(bytes(&netem(100)), bytes(&netem(100)));
        assert_ne!(bytes(&netem(100)), bytes(&netem(200)));
    }

    #[test]
    fn a_kind_without_options_matches_and_one_with_needs_them() {
        let htb = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x10));
        assert!(!htb.matches(&live("htb", None)));
        assert!(!htb.matches(&live("htb", Some(Vec::new()))));
        assert!(QdiscSpec::Clsact.matches(&live("clsact", Some(Vec::new()))));
        assert!(QdiscSpec::Clsact.matches(&live("clsact", None)));
        assert!(
            !QdiscSpec::Clsact.matches(&live("ingress", None)),
            "another kind"
        );
    }

    /// The kernel reports attributes netem was never sent (`ECN`, `CORR`,
    /// …). A spec must still match its own qdisc (#346).
    #[test]
    fn netem_matches_the_kernels_echo_with_extra_attributes() {
        use crate::netlink::types::tc::qdisc::netem::TCA_NETEM_ECN;
        let spec = netem(100);
        let mut echo = bytes(&spec);
        echo.extend(attr_u32(TCA_NETEM_ECN, 0));
        assert!(spec.matches(&live("netem", Some(echo.clone()))));
        assert!(!netem(200).matches(&live("netem", Some(echo))));
    }

    /// codel stores time in 2^-10 s units: a 20 ms target is echoed as
    /// 19999 µs. Compare in the kernel's quantisation, and only the fields
    /// the spec sets.
    #[test]
    fn fq_codel_compares_in_codel_ticks_and_only_set_fields() {
        use crate::netlink::types::tc::qdisc::fq_codel::{
            TCA_FQ_CODEL_ECN, TCA_FQ_CODEL_FLOWS, TCA_FQ_CODEL_QUANTUM, TCA_FQ_CODEL_TARGET,
        };
        let target = |ms| QdiscSpec::from(FqCodelConfig::new().target(Duration::from_millis(ms)));
        let echo = live("fq_codel", Some(attr_u32(TCA_FQ_CODEL_TARGET, 19_999)));
        assert!(target(20).matches(&echo));
        assert!(!target(18).matches(&echo));
        assert!(QdiscSpec::from(FqCodelConfig::new()).matches(&echo));

        let fq = |flows: Option<u32>, quantum: Option<u32>, ecn: Option<bool>| {
            let mut c = FqCodelConfig::new();
            c.flows = flows;
            c.quantum = quantum;
            c.ecn = ecn;
            QdiscSpec::from(c)
        };
        let mut opts = attr_u32(TCA_FQ_CODEL_FLOWS, 1024);
        opts.extend(attr_u32(TCA_FQ_CODEL_QUANTUM, 300));
        opts.extend(attr_u32(TCA_FQ_CODEL_ECN, 1));
        let echo = live("fq_codel", Some(opts));
        assert!(fq(Some(1024), Some(300), Some(true)).matches(&echo));
        assert!(
            fq(None, None, None).matches(&echo),
            "unset knobs are not compared"
        );
        assert!(
            !fq(Some(512), None, None).matches(&echo),
            "flows recreates, so it is seen (#596)"
        );
        assert!(!fq(None, Some(1514), None).matches(&echo));
        assert!(!fq(None, None, Some(false)).matches(&echo));
        // The kernel stores quantum as max(256, quantum).
        let echo = live("fq_codel", Some(attr_u32(TCA_FQ_CODEL_QUANTUM, 256)));
        assert!(fq(None, Some(128), None).matches(&echo));
        assert!(!fq(None, Some(300), None).matches(&echo));
    }

    #[test]
    fn htb_default_class_is_compared_as_a_field() {
        use crate::netlink::types::tc::qdisc::htb::TCA_HTB_DIRECT_QLEN;
        let spec = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x10));
        let mut echo = bytes(&spec);
        echo.extend(attr_u32(TCA_HTB_DIRECT_QLEN, 1000));
        assert!(spec.matches(&live("htb", Some(echo.clone()))));
        let other = QdiscSpec::from(HtbQdiscConfig::new().default_class(0x20));
        assert!(!other.matches(&live("htb", Some(echo))));
    }

    fn tbf(rate: u64, burst: u64, limit: u64, peak: Option<u64>, mtu: Option<u32>) -> QdiscSpec {
        let mut c = TbfConfig::new()
            .rate(Rate::bytes_per_sec(rate))
            .burst(Bytes::new(burst))
            .limit(Bytes::new(limit));
        c.peakrate = peak.map(Rate::bytes_per_sec);
        if let Some(mtu) = mtu {
            c.mtu = mtu;
        }
        c.into()
    }

    #[test]
    fn tbf_rate_burst_limit_peakrate_and_mtu_are_compared() {
        let spec = tbf(125_000, 32_768, 65_536, None, None);
        let echo = live("tbf", Some(bytes(&spec)));
        assert!(spec.matches(&echo));
        assert!(!tbf(250_000, 32_768, 65_536, None, None).matches(&echo));
        assert!(!tbf(125_000, 65_536, 65_536, None, None).matches(&echo));

        let peaked = tbf(125_000, 32_768, 65_536, Some(250_000), Some(1600));
        let peaked_echo = live("tbf", Some(bytes(&peaked)));
        assert!(peaked.matches(&peaked_echo));
        assert!(!tbf(125_000, 32_768, 65_536, Some(500_000), Some(1600)).matches(&peaked_echo));
        assert!(!tbf(125_000, 32_768, 65_536, Some(250_000), Some(9000)).matches(&peaked_echo));
        assert!(!spec.matches(&peaked_echo), "dropping the peakrate is seen");
    }

    /// What `tbf_dump()` sends back: `tc_tbf_qopt` alone, with `buffer`
    /// and `mtu` as psched ticks and no TCA_TBF_BURST/PBURST.
    fn kernel_tbf_echo(rate: u32, limit: u32, buffer_ticks: u32, mtu_ticks: u32) -> Vec<u8> {
        use crate::netlink::types::tc::qdisc::{TcRateSpec, tbf};
        let qopt = tbf::TcTbfQopt {
            rate: TcRateSpec::new(rate),
            peakrate: TcRateSpec::default(),
            limit,
            buffer: buffer_ticks,
            mtu: mtu_ticks,
        };
        let mut out = Vec::new();
        out.extend_from_slice(&((4 + tbf::TcTbfQopt::SIZE) as u16).to_ne_bytes());
        out.extend_from_slice(&tbf::TCA_TBF_PARMS.to_ne_bytes());
        out.extend_from_slice(qopt.as_bytes());
        out
    }

    /// 10 gbit, a 32 KiB burst, the default mtu: a 6.12 kernel dumps
    /// `buffer` 409 ticks and `mtu` 18, which read back as 32719 and 1440
    /// bytes; the comparison goes through the same round trip.
    #[test]
    fn tbf_buckets_are_compared_after_the_kernels_tick_round_trip() {
        let echo = live("tbf", Some(kernel_tbf_echo(1_250_000_000, 65_536, 409, 18)));
        assert!(tbf(1_250_000_000, 32_768, 65_536, None, None).matches(&echo));
        assert!(!tbf(1_250_000_000, 65_536, 65_536, None, None).matches(&echo));
        // Without a limit nothing matches, so an apply refuses it (the
        // kernel's limit-0 TBF drops everything).
        let black_hole = live("tbf", Some(kernel_tbf_echo(1_250_000_000, 0, 409, 18)));
        assert!(!tbf(1_250_000_000, 32_768, 0, None, None).matches(&black_hole));
        assert!(
            tbf(1_250_000_000, 32_768, 0, None, None)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn sfq_and_prio_compare_their_fields() {
        let sfq = |perturb: i32, limit: u32, quantum: u32| {
            let mut c = SfqConfig::new();
            c.perturb = perturb;
            c.limit = limit;
            c.quantum = quantum;
            QdiscSpec::from(c)
        };
        let tuned = sfq(10, 200, 1514);
        let echo = live("sfq", Some(bytes(&tuned)));
        assert!(tuned.matches(&echo));
        assert!(!sfq(20, 200, 1514).matches(&echo));
        // A limit or quantum of 0 leaves the kernel its default and is not
        // compared; the perturbation period is, 0 being "off".
        assert!(sfq(10, 0, 0).matches(&echo));
        assert!(
            !sfq(0, 0, 0).matches(&echo),
            "an unset perturb is the kernel's 0, not 10"
        );
        assert!(!sfq(10, 64, 0).matches(&echo));
        assert!(!sfq(10, 0, 300).matches(&echo));
        // The limit is capped at maxdepth * maxflows.
        let echo = live("sfq", Some(bytes(&sfq(0, 16_256, 0))));
        assert!(sfq(0, 20_000, 0).matches(&echo));
        assert!(!sfq(0, 16_000, 0).matches(&echo));

        let prio = |bands| QdiscSpec::from(PrioConfig::new().bands(bands));
        let echo = live("prio", Some(bytes(&prio(3))));
        assert!(prio(3).matches(&echo));
        assert!(!prio(4).matches(&echo));
    }

    #[test]
    fn a_spec_installs_as_its_config_does() {
        let spec = netem(100);
        let QdiscSpec::Netem(cfg) = &spec else {
            unreachable!()
        };
        assert_eq!(QdiscConfig::kind(&spec), "netem");
        assert_eq!(bytes(&spec), {
            let mut b = MessageBuilder::new(0, 0);
            let start = b.len();
            cfg.write_options(&mut b).unwrap();
            b.as_bytes()[start..].to_vec()
        });
        assert_eq!(QdiscSpec::Clsact.fixed_parent(), Some(TcHandle::INGRESS));
        assert_eq!(
            QdiscSpec::from(HtbQdiscConfig::new()).default_handle(),
            Some(TcHandle::major_only(1))
        );
        assert!(QdiscSpec::from(HtbQdiscConfig::new()).is_classful());
        assert!(!spec.is_classful());
        assert!(QdiscSpec::KernelDefault.validate().is_ok());
        let mut b = MessageBuilder::new(0, 0);
        assert!(QdiscSpec::KernelDefault.write_options(&mut b).is_err());
    }
}
