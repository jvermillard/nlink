//! Per-device IP settings over netlink (#516): the IPv4 devconf
//! (`/proc/sys/net/ipv4/conf/<dev>/…`), which a link dump reports and
//! `RTM_SETLINK` writes, and the IPv6 address generation mode and token.
//!
//! Both live in a link's `IFLA_AF_SPEC`, nested by family:
//!
//! ```text
//! IFLA_AF_SPEC
//!   AF_INET   { IFLA_INET_CONF: u32[IPV4_DEVCONF_MAX] }   (dump: an array; set: nested by id)
//!   AF_INET6  { IFLA_INET6_CONF: s32[DEVCONF_MAX], IFLA_INET6_TOKEN, IFLA_INET6_ADDR_GEN_MODE: u8 }
//! ```
//!
//! The rest of the IPv6 devconf (`accept_dad`, `disable_ipv6`, …) the kernel
//! reports here but only takes through `/proc/sys`.

use std::net::Ipv6Addr;

use super::attr::AttrIter;

/// An IPv4 per-device setting (`IPV4_DEVCONF_*`): the file of that name in
/// `/proc/sys/net/ipv4/conf/<dev>/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
#[non_exhaustive]
pub enum Ipv4Devconf {
    Forwarding = 1,
    McForwarding = 2,
    ProxyArp = 3,
    AcceptRedirects = 4,
    SecureRedirects = 5,
    SendRedirects = 6,
    SharedMedia = 7,
    RpFilter = 8,
    AcceptSourceRoute = 9,
    BootpRelay = 10,
    LogMartians = 11,
    Tag = 12,
    ArpFilter = 13,
    MediumId = 14,
    NoXfrm = 15,
    NoPolicy = 16,
    ForceIgmpVersion = 17,
    ArpAnnounce = 18,
    ArpIgnore = 19,
    PromoteSecondaries = 20,
    ArpAccept = 21,
    ArpNotify = 22,
    AcceptLocal = 23,
    SrcVmark = 24,
    ProxyArpPvlan = 25,
    RouteLocalnet = 26,
    Igmpv2UnsolicitedReportInterval = 27,
    Igmpv3UnsolicitedReportInterval = 28,
    IgnoreRoutesWithLinkdown = 29,
    DropUnicastInL2Multicast = 30,
    DropGratuitousArp = 31,
    BcForwarding = 32,
    ArpEvictNocarrier = 33,
}

impl Ipv4Devconf {
    /// Every setting, in id order.
    pub const ALL: [Self; 33] = [
        Self::Forwarding,
        Self::McForwarding,
        Self::ProxyArp,
        Self::AcceptRedirects,
        Self::SecureRedirects,
        Self::SendRedirects,
        Self::SharedMedia,
        Self::RpFilter,
        Self::AcceptSourceRoute,
        Self::BootpRelay,
        Self::LogMartians,
        Self::Tag,
        Self::ArpFilter,
        Self::MediumId,
        Self::NoXfrm,
        Self::NoPolicy,
        Self::ForceIgmpVersion,
        Self::ArpAnnounce,
        Self::ArpIgnore,
        Self::PromoteSecondaries,
        Self::ArpAccept,
        Self::ArpNotify,
        Self::AcceptLocal,
        Self::SrcVmark,
        Self::ProxyArpPvlan,
        Self::RouteLocalnet,
        Self::Igmpv2UnsolicitedReportInterval,
        Self::Igmpv3UnsolicitedReportInterval,
        Self::IgnoreRoutesWithLinkdown,
        Self::DropUnicastInL2Multicast,
        Self::DropGratuitousArp,
        Self::BcForwarding,
        Self::ArpEvictNocarrier,
    ];

    /// The sysctl's name: `rp_filter` for [`Self::RpFilter`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Forwarding => "forwarding",
            Self::McForwarding => "mc_forwarding",
            Self::ProxyArp => "proxy_arp",
            Self::AcceptRedirects => "accept_redirects",
            Self::SecureRedirects => "secure_redirects",
            Self::SendRedirects => "send_redirects",
            Self::SharedMedia => "shared_media",
            Self::RpFilter => "rp_filter",
            Self::AcceptSourceRoute => "accept_source_route",
            Self::BootpRelay => "bootp_relay",
            Self::LogMartians => "log_martians",
            Self::Tag => "tag",
            Self::ArpFilter => "arp_filter",
            Self::MediumId => "medium_id",
            Self::NoXfrm => "disable_xfrm",
            Self::NoPolicy => "disable_policy",
            Self::ForceIgmpVersion => "force_igmp_version",
            Self::ArpAnnounce => "arp_announce",
            Self::ArpIgnore => "arp_ignore",
            Self::PromoteSecondaries => "promote_secondaries",
            Self::ArpAccept => "arp_accept",
            Self::ArpNotify => "arp_notify",
            Self::AcceptLocal => "accept_local",
            Self::SrcVmark => "src_valid_mark",
            Self::ProxyArpPvlan => "proxy_arp_pvlan",
            Self::RouteLocalnet => "route_localnet",
            Self::Igmpv2UnsolicitedReportInterval => "igmpv2_unsolicited_report_interval",
            Self::Igmpv3UnsolicitedReportInterval => "igmpv3_unsolicited_report_interval",
            Self::IgnoreRoutesWithLinkdown => "ignore_routes_with_linkdown",
            Self::DropUnicastInL2Multicast => "drop_unicast_in_l2_multicast",
            Self::DropGratuitousArp => "drop_gratuitous_arp",
            Self::BcForwarding => "bc_forwarding",
            Self::ArpEvictNocarrier => "arp_evict_nocarrier",
        }
    }

    /// The setting with sysctl name `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }

    /// The kernel's id (`IPV4_DEVCONF_*`).
    pub fn id(self) -> u16 {
        self as u16
    }
}

impl std::fmt::Display for Ipv4Devconf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How the kernel makes a link's IPv6 link-local address (`IN6_ADDR_GEN_MODE_*`,
/// `ip link set … addrgenmode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AddrGenMode {
    /// From the MAC address (the default).
    Eui64 = 0,
    /// None: the link gets no link-local address.
    None = 1,
    /// RFC 7217, from `stable_secret`.
    StablePrivacy = 2,
    /// Random.
    Random = 3,
}

impl AddrGenMode {
    /// The mode `ip link` names `name` (`eui64`, `none`,
    /// `stable_secret`, `random`).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "eui64" => Self::Eui64,
            "none" => Self::None,
            "stable_secret" | "stable-privacy" => Self::StablePrivacy,
            "random" => Self::Random,
            _ => return None,
        })
    }

    /// The name `ip link` gives it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Eui64 => "eui64",
            Self::None => "none",
            Self::StablePrivacy => "stable_secret",
            Self::Random => "random",
        }
    }

    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Eui64,
            1 => Self::None,
            2 => Self::StablePrivacy,
            3 => Self::Random,
            _ => return None,
        })
    }
}

/// `IFLA_INET_*` and `IFLA_INET6_*` (`linux/if_link.h`).
pub(crate) mod af {
    pub const IFLA_INET_CONF: u16 = 1;
    pub const IFLA_INET6_CONF: u16 = 2;
    pub const IFLA_INET6_TOKEN: u16 = 7;
    pub const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
}

/// What a link's `IFLA_AF_SPEC` says of IPv4 and IPv6.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InetAfSpec {
    /// `IFLA_INET_CONF`: entry `i` is `IPV4_DEVCONF` id `i + 1`.
    pub(crate) ipv4_conf: Option<Vec<u32>>,
    /// `IFLA_INET6_CONF`: entry `i` is `DEVCONF` id `i`.
    pub(crate) ipv6_conf: Option<Vec<i32>>,
    pub(crate) ipv6_token: Option<Ipv6Addr>,
    pub(crate) addr_gen_mode: Option<u8>,
}

impl InetAfSpec {
    /// Read the `AF_INET` and `AF_INET6` nests of an `IFLA_AF_SPEC`
    /// payload; the other families are not this one's.
    pub(crate) fn parse(af_spec: &[u8]) -> Self {
        let words = |p: &[u8]| -> Vec<[u8; 4]> { p.as_chunks::<4>().0.to_vec() };
        let mut out = Self::default();
        for (family, nest) in AttrIter::new(af_spec) {
            match i32::from(family & 0x3FFF) {
                libc::AF_INET => {
                    for (t, p) in AttrIter::new(nest) {
                        if t & 0x3FFF == af::IFLA_INET_CONF {
                            out.ipv4_conf =
                                Some(words(p).into_iter().map(u32::from_ne_bytes).collect());
                        }
                    }
                }
                libc::AF_INET6 => {
                    for (t, p) in AttrIter::new(nest) {
                        match t & 0x3FFF {
                            af::IFLA_INET6_CONF => {
                                out.ipv6_conf =
                                    Some(words(p).into_iter().map(i32::from_ne_bytes).collect());
                            }
                            af::IFLA_INET6_TOKEN => {
                                if let Ok(b) = <[u8; 16]>::try_from(p.get(..16).unwrap_or(&[])) {
                                    out.ipv6_token = Some(Ipv6Addr::from(b));
                                }
                            }
                            af::IFLA_INET6_ADDR_GEN_MODE => out.addr_gen_mode = p.first().copied(),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// An IPv4 setting's value.
    pub(crate) fn ipv4(&self, d: Ipv4Devconf) -> Option<u32> {
        self.ipv4_conf
            .as_ref()?
            .get(usize::from(d.id()) - 1)
            .copied()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AddrGenMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AddrGenMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Self::from_name(&name).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown addrgenmode {name:?} (eui64, none, stable_secret, random)"
            ))
        })
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for AddrGenMode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AddrGenMode".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "enum": ["eui64", "none", "stable_secret", "random"] })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ipv4Devconf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Ipv4Devconf {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ipv4Devconf".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|d| d.name()).collect();
        schemars::json_schema!({ "enum": names })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::builder::MessageBuilder;

    #[test]
    fn names_round_trip_and_ids_are_dense() {
        for (i, d) in Ipv4Devconf::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(d.id()), i + 1);
            assert_eq!(Ipv4Devconf::from_name(d.name()), Some(d));
        }
        for m in [AddrGenMode::Eui64, AddrGenMode::None, AddrGenMode::StablePrivacy, AddrGenMode::Random] {
            assert_eq!(AddrGenMode::from_name(m.name()), Some(m));
            assert_eq!(AddrGenMode::from_u8(m as u8), Some(m));
        }
    }

    #[test]
    fn an_af_spec_is_read_by_family() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        let inet = b.nest_start(libc::AF_INET as u16);
        let conf: Vec<u8> = (1u32..=33).flat_map(|v| v.to_ne_bytes()).collect();
        b.append_attr(af::IFLA_INET_CONF, &conf);
        b.nest_end(inet);
        let inet6 = b.nest_start(libc::AF_INET6 as u16);
        b.append_attr_u8(af::IFLA_INET6_ADDR_GEN_MODE, 1);
        b.append_attr(af::IFLA_INET6_TOKEN, &"::1:2".parse::<Ipv6Addr>().unwrap().octets());
        b.nest_end(inet6);
        let spec = InetAfSpec::parse(&b.as_bytes()[start..]);
        assert_eq!(spec.ipv4(Ipv4Devconf::Forwarding), Some(1));
        assert_eq!(spec.ipv4(Ipv4Devconf::RpFilter), Some(8));
        assert_eq!(spec.ipv4(Ipv4Devconf::ArpEvictNocarrier), Some(33));
        assert_eq!(spec.addr_gen_mode, Some(1));
        assert_eq!(spec.ipv6_token, Some("::1:2".parse().unwrap()));
    }
}
