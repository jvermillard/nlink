//! Transition matrices: every declared field changed from one value to
//! another in a single apply, which must converge (the diff empty after
//! it, a second apply changing nothing). Most of 0.30's bugs needed a
//! change in place to show (#534); the cases here cover the fields no
//! issue named.

use std::net::{IpAddr, Ipv4Addr};

use nlink::netlink::config::{
    BondAdSelect, BondLacpRate, BondMode, BondXmitHashPolicy, MacvlanMode, NetworkConfig,
    VlanProtocol,
};

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, case, ip_json};

const MAC_A: [u8; 6] = [0x02, 0x00, 0x5e, 0x20, 0x00, 0x01];
const MAC_B: [u8; 6] = [0x02, 0x00, 0x5e, 0x20, 0x00, 0x02];

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The kernel's `ip -j -d link show dev <dev>` object, through `ip`, not
/// nlink: a diff that does not compare a field agrees with anything.
fn link_json(ns: &TestNamespace, dev: &str) -> Result<serde_json::Value, String> {
    let all = ip_json(ns, &["-d", "link", "show", "dev", dev])?;
    Ok(all[0].clone())
}

/// A check that `dev`'s `ip -j -d link` holds each `(path, value)`, with
/// `path` dotted (`linkinfo.info_data.mode`).
fn expect_link(
    dev: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let link = link_json(ns, dev)?;
        for (path, value) in want {
            let mut at = &link;
            for key in path.split('.') {
                at = &at[key];
            }
            let got = match at {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{dev} {path}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A check that `ip -j route show table all <dst>` lists exactly one route,
/// whose fields hold each `(key, value)` — `type` is "unicast" when `ip`
/// leaves it out.
fn expect_route(
    family: &'static str,
    dst: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let routes = ip_json(ns, &[family, "route", "show", "table", "all", dst])?;
        let routes = routes.as_array().cloned().unwrap_or_default();
        let [route] = routes.as_slice() else {
            return Err(format!("{dst}: want one route, the kernel has {routes:?}"));
        };
        for (key, value) in want {
            let got = match &route[*key] {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null if *key == "type" => "unicast".to_string(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{dst} {key}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A check that `d0`'s root qdisc is `kind`, with each `(option, value)`
/// in `tc -j qdisc show`'s options.
fn expect_qdisc(
    kind: &'static str,
    want: &'static [(&'static str, &'static str)],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let out = ns
            .exec("tc", &["-j", "qdisc", "show", "dev", "d0"])
            .map_err(|e| e.to_string())?;
        let qdiscs: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let root = qdiscs
            .as_array()
            .and_then(|q| {
                q.iter()
                    .find(|q| q["root"] == serde_json::Value::Bool(true))
            })
            .ok_or_else(|| format!("no root qdisc: {out}"))?;
        if root["kind"] != kind {
            return Err(format!("root is {}, not {kind}", root["kind"]));
        }
        for (key, value) in want {
            let got = match &root["options"][*key] {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if got != *value {
                return Err(format!("{kind} {key}: want {value}, the kernel has {got}"));
            }
        }
        Ok(())
    }
}

/// A dummy `d0` up, plus whatever `f` declares on it.
fn dummy(
    f: impl FnOnce(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder + 'static,
) -> NetworkConfig {
    NetworkConfig::new().link("d0", move |l| f(l.dummy().up()))
}

#[tokio::test]
async fn link_fields_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy", "bridge", "8021q", "vxlan", "macvlan", "bonding", "vrf"
    );

    let two_bridges = |master: Option<&'static str>| {
        NetworkConfig::new()
            .link("br0", |l| l.bridge().up())
            .link("br1", |l| l.bridge().up())
            .link("d0", move |l| match master {
                Some(m) => l.dummy().up().master(m),
                None => l.dummy().up().nomaster(),
            })
    };
    let vlan = |proto: VlanProtocol| {
        dummy(|l| l).link("v0", move |l| l.vlan("d0", 10).vlan_protocol(proto).up())
    };
    let vxlan = |remote: IpAddr, local: IpAddr, port: u16, under: &'static str| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .address("d0", "10.30.0.1/24")
            .unwrap()
            .address("d1", "10.31.0.1/24")
            .unwrap()
            .link("vx0", move |l| {
                l.vxlan(100)
                    .vxlan_remote(remote)
                    .vxlan_local(local)
                    .vxlan_port(port)
                    .vxlan_underlay_dev(under)
                    .up()
            })
    };
    let macvlan = |mode: MacvlanMode| {
        dummy(|l| l).link("mv0", move |l| l.macvlan("d0").macvlan_mode(mode).up())
    };
    let bond =
        |f: fn(nlink::netlink::config::LinkBuilder) -> nlink::netlink::config::LinkBuilder| {
            NetworkConfig::new().link("bond0", move |l| f(l.bond()).up())
        };

    let cases = vec![
        case(
            "mtu",
            vec![
                dummy(|l| l.mtu(1400)),
                dummy(|l| l.mtu(1500)),
                dummy(|l| l.mtu(9000)),
            ],
        )
        .check(expect_link("d0", &[("mtu", "9000")])),
        case(
            "state",
            vec![
                NetworkConfig::new().link("d0", |l| l.dummy().up()),
                NetworkConfig::new().link("d0", |l| l.dummy().down()),
                NetworkConfig::new().link("d0", |l| l.dummy().up()),
            ],
        ),
        case(
            "mac",
            vec![dummy(|l| l.address(MAC_A)), dummy(|l| l.address(MAC_B))],
        )
        .check(expect_link("d0", &[("address", "02:00:5e:20:00:02")])),
        case(
            "master",
            vec![
                two_bridges(Some("br0")),
                two_bridges(Some("br1")),
                two_bridges(None),
            ],
        )
        .check(expect_link("d0", &[("master", "null")])),
        case(
            "vlan-protocol",
            vec![vlan(VlanProtocol::Dot1q), vlan(VlanProtocol::Dot1ad)],
        )
        .check(expect_link(
            "v0",
            &[("linkinfo.info_data.protocol", "802.1ad")],
        )),
        case(
            "vxlan-remote",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 30, 0, 3), v4(10, 30, 0, 1), 4789, "d0"),
            ],
        )
        .check(expect_link(
            "vx0",
            &[("linkinfo.info_data.remote", "10.30.0.3")],
        )),
        case(
            "vxlan-local-and-underlay",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 31, 0, 2), v4(10, 31, 0, 1), 4789, "d1"),
            ],
        )
        .check(expect_link(
            "vx0",
            &[
                ("linkinfo.info_data.local", "10.31.0.1"),
                ("linkinfo.info_data.link", "d1"),
            ],
        )),
        case(
            "vxlan-port",
            vec![
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4789, "d0"),
                vxlan(v4(10, 30, 0, 2), v4(10, 30, 0, 1), 4790, "d0"),
            ],
        )
        .check(expect_link("vx0", &[("linkinfo.info_data.port", "4790")])),
        case(
            "macvlan-mode",
            vec![
                macvlan(MacvlanMode::Bridge),
                macvlan(MacvlanMode::Private),
                macvlan(MacvlanMode::Vepa),
            ],
        )
        .check(expect_link("mv0", &[("linkinfo.info_data.mode", "vepa")])),
        case(
            "bond-miimon-and-delays",
            vec![
                bond(|b| b.bond_mode(BondMode::ActiveBackup).miimon(100)),
                bond(|b| {
                    b.bond_mode(BondMode::ActiveBackup)
                        .miimon(200)
                        .bond_updelay(400)
                        .bond_downdelay(200)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.miimon", "200"),
                ("linkinfo.info_data.updelay", "400"),
                ("linkinfo.info_data.downdelay", "200"),
            ],
        )),
        case(
            "bond-hash-policy-and-min-links",
            vec![
                bond(|b| {
                    b.bond_mode(BondMode::BalanceXor)
                        .xmit_hash_policy(BondXmitHashPolicy::Layer2)
                }),
                bond(|b| {
                    b.bond_mode(BondMode::BalanceXor)
                        .xmit_hash_policy(BondXmitHashPolicy::Layer34)
                        .min_links(1)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.xmit_hash_policy", "layer3+4"),
                ("linkinfo.info_data.min_links", "1"),
            ],
        )),
        case(
            "bond-lacp",
            vec![
                bond(|b| {
                    b.bond_mode(BondMode::Ieee802_3ad)
                        .bond_lacp_rate(BondLacpRate::Slow)
                        .bond_ad_select(BondAdSelect::Stable)
                }),
                bond(|b| {
                    b.bond_mode(BondMode::Ieee802_3ad)
                        .bond_lacp_rate(BondLacpRate::Fast)
                        .bond_ad_select(BondAdSelect::Bandwidth)
                }),
            ],
        )
        .check(expect_link(
            "bond0",
            &[
                ("linkinfo.info_data.ad_lacp_rate", "fast"),
                ("linkinfo.info_data.ad_select", "bandwidth"),
            ],
        )),
        case(
            "bond-resend-igmp",
            vec![
                bond(|b| b.bond_mode(BondMode::ActiveBackup).bond_resend_igmp(1)),
                bond(|b| b.bond_mode(BondMode::ActiveBackup).bond_resend_igmp(3)),
            ],
        )
        .check(expect_link(
            "bond0",
            &[("linkinfo.info_data.resend_igmp", "3")],
        )),
        case(
            "vrf-table",
            vec![
                NetworkConfig::new().link("vrf0", |l| l.vrf(10).up()),
                NetworkConfig::new().link("vrf0", |l| l.vrf(20).up()),
            ],
        )
        .check(expect_link("vrf0", &[("linkinfo.info_data.table", "20")])),
    ];
    assert_converges("tm-link", cases).await
}

#[tokio::test]
async fn route_fields_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let base = || {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("d1", |l| l.dummy().up())
            .address("d0", "10.40.0.1/24")
            .unwrap()
            .address("d1", "10.41.0.1/24")
            .unwrap()
            .address("d0", "fd00:40::1/64")
            .unwrap()
    };
    let via = |gw: &'static str| base().route("10.99.0.0/16", move |r| r.via(gw)).unwrap();
    let through = |dev: &'static str| base().route("10.99.0.0/16", move |r| r.dev(dev)).unwrap();
    let table = |t: u32| {
        base()
            .route("10.99.0.0/16", move |r| r.via("10.40.0.254").table(t))
            .unwrap()
    };
    let kind = |k: &'static str| {
        base()
            .route("10.99.0.0/16", move |r| match k {
                "blackhole" => r.blackhole(),
                "unreachable" => r.unreachable(),
                "prohibit" => r.prohibit(),
                _ => r.via("10.40.0.254"),
            })
            .unwrap()
    };
    let default = |gw: &'static str| base().route("0.0.0.0/0", move |r| r.via(gw)).unwrap();
    let v6 = |gw: &'static str| {
        base()
            .route("2001:db8:99::/48", move |r| r.via(gw))
            .unwrap()
    };

    let cases = vec![
        case("gateway", vec![via("10.40.0.254"), via("10.40.0.253")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("gateway", "10.40.0.253")],
        )),
        case("device", vec![through("d0"), through("d1")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("dev", "d1")],
        )),
        case("gateway-to-device", vec![via("10.40.0.254"), through("d1")]).check(expect_route(
            "-4",
            "10.99.0.0/16",
            &[("dev", "d1"), ("gateway", "null")],
        )),
        // The route in table 100 stays: once nothing declares into a table
        // it is out of the purge's scope (#333/#335, `purge_tables`), and
        // which tables a config owns is #512's question.
        case("table", vec![table(100), table(200)]).purging(),
        case(
            "type",
            vec![
                kind("unicast"),
                kind("blackhole"),
                kind("unreachable"),
                kind("prohibit"),
                kind("unicast"),
            ],
        )
        .purging()
        .check(expect_route("-4", "10.99.0.0/16", &[("type", "unicast")])),
        case(
            "default-gateway",
            vec![default("10.40.0.254"), default("10.40.0.253")],
        )
        .check(expect_route("-4", "default", &[("gateway", "10.40.0.253")])),
        case("v6-gateway", vec![v6("fd00:40::fe"), v6("fd00:40::fd")]).check(expect_route(
            "-6",
            "2001:db8:99::/48",
            &[("gateway", "fd00:40::fd")],
        )),
    ];
    assert_converges("tm-route", cases).await
}

#[tokio::test]
async fn qdisc_fields_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!(
        "dummy",
        "sch_netem",
        "sch_htb",
        "sch_tbf",
        "sch_sfq",
        "sch_prio"
    );

    let q =
        |f: fn(nlink::netlink::config::QdiscBuilder) -> nlink::netlink::config::QdiscBuilder| {
            dummy(|l| l).qdisc("d0", f)
        };
    let cases = vec![
        case(
            "fq-codel",
            vec![
                q(|q| q.fq_codel().limit(1000).flows(512).quantum(1514)),
                q(|q| {
                    q.fq_codel()
                        .limit(2000)
                        .flows(1024)
                        .quantum(3028)
                        .target(Duration::from_millis(10))
                        .interval(Duration::from_millis(200))
                }),
            ],
        )
        // `flows` is left out: a declared change never reaches the kernel
        // (#596).
        .check(expect_qdisc(
            "fq_codel",
            // In µs after codel's 2^-10 s round trip: 10 ms, 200 ms.
            &[
                ("limit", "2000"),
                ("quantum", "3028"),
                ("target", "9999"),
                ("interval", "199999"),
            ],
        )),
        case(
            "sfq",
            vec![
                q(|q| q.sfq().perturb(Duration::from_secs(10)).quantum(1514)),
                q(|q| q.sfq().perturb(Duration::from_secs(20)).quantum(3028)),
            ],
        )
        .check(expect_qdisc(
            "sfq",
            &[("perturb", "20"), ("quantum", "3028")],
        )),
        case(
            "prio-bands-and-priomap",
            vec![
                q(|q| q.prio().bands(3)),
                q(|q| {
                    q.prio()
                        .bands(4)
                        .priomap([1, 2, 3, 0, 1, 2, 3, 0, 1, 1, 1, 1, 1, 1, 1, 1])
                }),
            ],
        )
        .check(expect_qdisc("prio", &[("bands", "4")])),
        case(
            "kind-changes",
            vec![
                q(|q| q.netem().delay_ms(5)),
                q(|q| q.fq_codel()),
                q(|q| q.sfq()),
                q(|q| q.prio().bands(3)),
                q(|q| q.htb()),
                q(|q| q.netem().delay_ms(5)),
            ],
        )
        .check(expect_qdisc("netem", &[])),
        case(
            "ingress-to-clsact",
            vec![
                dummy(|l| l).qdisc("d0", |q| q.ingress()),
                dummy(|l| l).qdisc("d0", |q| q.clsact()),
            ],
        ),
    ];
    assert_converges("tm-qdisc", cases).await
}

// ============================================================================
// nftables
// ============================================================================

/// `nft list <what>` inside `ns`.
fn nft_list(ns: &TestNamespace, what: &[&str]) -> Result<String, String> {
    let mut args = vec!["list"];
    args.extend_from_slice(what);
    ns.exec("nft", &args).map_err(|e| e.to_string())
}

/// A check that `nft list <what>` shows every one of `want`.
fn expect_nft(
    what: &'static [&'static str],
    want: &'static [&'static str],
) -> impl Fn(&TestNamespace) -> Result<(), String> + 'static {
    move |ns| {
        let shown = nft_list(ns, what)?;
        for line in want {
            if !shown.contains(line) {
                return Err(format!("nft does not show `{line}`:\n{shown}"));
            }
        }
        Ok(())
    }
}

#[tokio::test]
async fn nftables_fields_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;

    use nlink::netlink::nftables::config::NftablesConfig;
    use nlink::netlink::nftables::types::{
        ChainType, Family, Hook, Priority, SetDataType, SetElement, SetKeyType,
    };
    use nlink::netlink::nftables::{LimitExpr, ObjectConfig, QuotaExpr};
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota", "nft_limit");

    let table = |f: fn(
        nlink::netlink::nftables::config::DeclaredTableBuilder,
    ) -> nlink::netlink::nftables::config::DeclaredTableBuilder| {
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            f(t.chain("out", |c| {
                c.hook(Hook::Output)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
            }))
        })
    };

    let cases = vec![
        case(
            "set-size-timeout-gc",
            vec![
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .size(64)
                            .timeout(Duration::from_secs(60))
                            .gc_interval(Duration::from_secs(10))
                    })
                }),
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .size(128)
                            .timeout(Duration::from_secs(120))
                            .gc_interval(Duration::from_secs(20))
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["size 128", "timeout 2m", "gc-interval 20s"],
        )),
        case(
            "set-flags-recreate",
            vec![
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .element(SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1)))
                    })
                }),
                table(|t| {
                    t.set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .interval()
                            .element(SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1)))
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["flags interval", "10.50.0.1"],
        )),
        case(
            "set-key-type-recreate",
            vec![
                table(|t| t.set("s", |s| s.key_type(SetKeyType::Ipv4Addr))),
                table(|t| t.set("s", |s| s.key_type(SetKeyType::InetService).port(80))),
            ],
        )
        .check(expect_nft(
            &["set", "ip", "t", "s"],
            &["type inet_service", "80"],
        )),
        case(
            "map-data",
            vec![
                table(|t| {
                    t.set("m", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .map(SetDataType::Value(SetKeyType::Mark))
                            .element(
                                SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1))
                                    .value(SetElement::new(1u32.to_be_bytes().to_vec())),
                            )
                    })
                }),
                table(|t| {
                    t.set("m", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .map(SetDataType::Value(SetKeyType::Mark))
                            .element(
                                SetElement::ipv4(Ipv4Addr::new(10, 50, 0, 1))
                                    .value(SetElement::new(2u32.to_be_bytes().to_vec())),
                            )
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["map", "ip", "t", "m"],
            &["10.50.0.1 : 0x00000002"],
        )),
        case(
            "quota-size-and-over",
            vec![
                table(|t| t.object("q", ObjectConfig::Quota(QuotaExpr::new(1_000_000)))),
                table(|t| t.object("q", ObjectConfig::Quota(QuotaExpr::new(2_000_000).over()))),
            ],
        )
        .check(expect_nft(
            &["quota", "ip", "t", "q"],
            &["over 2000000 bytes"],
        )),
        case(
            "limit-rate",
            vec![
                table(|t| {
                    t.object(
                        "l",
                        ObjectConfig::Limit(LimitExpr::packets(
                            10,
                            nlink::netlink::nftables::types::LimitUnit::Second,
                        )),
                    )
                }),
                table(|t| {
                    t.object(
                        "l",
                        ObjectConfig::Limit(LimitExpr::packets(
                            20,
                            nlink::netlink::nftables::types::LimitUnit::Minute,
                        )),
                    )
                }),
            ],
        )
        .check(expect_nft(&["limit", "ip", "t", "l"], &["rate 20/minute"])),
        case(
            "rule-body-and-comment",
            vec![
                table(|t| t.rule_keyed("out", "r", |r| r.match_tcp_dport(22).accept())),
                table(|t| {
                    t.rule_keyed("out", "r", |r| {
                        r.match_tcp_dport(2222).drop().comment("moved")
                    })
                }),
            ],
        )
        .check(expect_nft(
            &["chain", "ip", "t", "out"],
            &["tcp dport 2222 drop"],
        )),
    ];
    assert_converges("tm-nft", cases).await
}

// ============================================================================
// Boundaries
// ============================================================================

/// The edges of the inputs that take numbers and names. What #598 lists
/// — names `validate()` misses, `"."`/`".."`/`":"` reaching the kernel,
/// VLAN ids past 4094, a NaN percentage — is left out until it is fixed.
#[tokio::test]
async fn boundaries() -> nlink::Result<()> {
    use nlink::netlink::link::DummyLink;
    use nlink::netlink::tc::NetemConfig;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_netem");

    let ns = TestNamespace::new("boundaries")?;
    let conn = ns.connection()?;

    // Interface names: refused before the kernel, or created.
    for name in ["", "a/b", "a b", "sixteen-bytes-xx"] {
        let err = conn.add_link(DummyLink::new(name)).await.expect_err(name);
        assert!(matches!(err, nlink::Error::Interface(_)), "{name:?}: {err}");
    }
    conn.add_link(DummyLink::new("fifteen-bytes-x")).await?;
    conn.add_link(DummyLink::new("d0")).await?;

    // VLAN ids 0 (priority-tagged) and 4094 are VLANs.
    for id in [0u16, 4094] {
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link(format!("v{id}").as_str(), move |l| l.vlan("d0", id));
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "vlan {id}: {applied:?}");
    }

    // Prefix lengths are checked as they parse.
    for (route, ok) in [
        ("0.0.0.0/0", true),
        ("10.0.0.1/32", true),
        ("10.0.0.0/33", false),
        ("::/0", true),
        ("2001:db8::/128", true),
        ("2001:db8::/129", false),
    ] {
        let parsed = NetworkConfig::new().route(route, |r| r.dev("d0"));
        assert_eq!(parsed.is_ok(), ok, "{route}");
    }

    // Percentages clamp to 0..=100.
    assert_eq!(nlink::Percent::new(150.0).as_percent(), 100.0);
    assert_eq!(nlink::Percent::new(-5.0).as_percent(), 0.0);

    // `ffff:` is the ingress/clsact handle, refused at the root.
    let err = conn
        .add_qdisc_full(
            "d0",
            nlink::TcHandle::ROOT,
            Some(nlink::TcHandle::major_only(0xffff)),
            NetemConfig::new().build(),
        )
        .await
        .expect_err("ffff: at the root");
    assert!(err.to_string().contains("reserved"), "{err}");
    Ok(())
}

// ============================================================================
// Reference parity: the same tc(8) lines through tc and through nlink
// ============================================================================

/// Thirteen ordinary flower lines, installed with `tc` in one namespace
/// and with `FlowerFilter::parse_params` in another, must dump the same:
/// the 0.30 cycle found three silent disagreements this way by hand
/// (#432, #433, #447). A filter's options are compared as `tc -j` prints
/// them.
#[tokio::test]
async fn flower_lines_install_the_same_through_tc_and_nlink() -> nlink::Result<()> {
    use nlink::TcHandle;
    use nlink::netlink::filter::FlowerFilter;
    use nlink::netlink::link::DummyLink;
    use nlink::netlink::tc::{HtbClassConfig, HtbQdiscConfig};
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "cls_flower");

    const LINES: &[(&str, u16, &str)] = &[
        ("ip", 0x0800, "dst_ip 10.0.0.1"),
        ("ip", 0x0800, "src_ip 10.0.0.0/24"),
        ("ip", 0x0800, "ip_proto tcp dst_port 80"),
        ("ip", 0x0800, "ip_proto udp src_port 53"),
        ("ip", 0x0800, "ip_proto tcp dst_port 1000-2000"),
        ("ip", 0x0800, "ip_tos 0x10/0xfc"),
        ("ip", 0x0800, "ip_ttl 64"),
        ("ip", 0x0800, "ip_proto tcp tcp_flags 0x02/0x12"),
        ("ipv6", 0x86dd, "dst_ip fd00::1"),
        ("ipv6", 0x86dd, "src_ip fd00::/64"),
        ("ipv6", 0x86dd, "ip_proto tcp src_port 443"),
        ("all", 0x0003, "dst_mac 02:00:00:00:00:01"),
        ("802.1q", 0x8100, "vlan_id 10 vlan_prio 3"),
    ];

    let build = |label: &str| -> nlink::Result<(TestNamespace, nlink::Connection<nlink::Route>)> {
        let ns = TestNamespace::new(label)?;
        let conn = ns.connection()?;
        Ok((ns, conn))
    };
    let (by_tc, tc_conn) = build("parity-tc")?;
    let (by_nlink, conn) = build("parity-nlink")?;
    for c in [&tc_conn, &conn] {
        c.add_link(DummyLink::new("d0")).await?;
        c.set_link_up("d0").await?;
        c.add_qdisc_full(
            "d0",
            TcHandle::ROOT,
            Some(TcHandle::major_only(1)),
            HtbQdiscConfig::new().build(),
        )
        .await?;
        c.add_class(
            "d0",
            TcHandle::major_only(1),
            TcHandle::new(1, 0x10),
            HtbClassConfig::new(nlink::Rate::mbit(10)).build(),
        )
        .await?;
    }
    for (i, (proto, proto_id, params)) in LINES.iter().enumerate() {
        let prio = (i + 1).to_string();
        let mut args = vec![
            "filter", "add", "dev", "d0", "parent", "1:", "protocol", proto, "prio", &prio,
            "flower",
        ];
        args.extend(params.split_whitespace());
        args.extend(["classid", "1:10"]);
        by_tc.exec("tc", &args)?;

        let mut tokens: Vec<&str> = params.split_whitespace().collect();
        tokens.extend(["classid", "1:10"]);
        let filter = FlowerFilter::parse_params(&tokens)?;
        conn.add_filter_full(
            "d0",
            TcHandle::major_only(1),
            None,
            *proto_id,
            (i + 1) as u16,
            filter,
        )
        .await?;
    }

    let dump = |ns: &TestNamespace| -> nlink::Result<Vec<serde_json::Value>> {
        let out = ns.exec("tc", &["-j", "filter", "show", "dev", "d0", "parent", "1:"])?;
        let all: serde_json::Value =
            serde_json::from_str(&out).map_err(|e| nlink::Error::InvalidMessage(e.to_string()))?;
        // The per-priority chain heads carry no options; compare filters.
        Ok(all
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.get("options").is_some())
            .collect())
    };
    let (want, got) = (dump(&by_tc)?, dump(&by_nlink)?);
    assert_eq!(
        want.len(),
        LINES.len(),
        "tc installed {} filters",
        want.len()
    );
    let mut differ = Vec::new();
    for (i, (w, g)) in want.iter().zip(&got).enumerate() {
        if w != g {
            differ.push(format!("{}\n  tc:    {w}\n  nlink: {g}", LINES[i].2));
        }
    }
    assert_eq!(
        got.len(),
        want.len(),
        "nlink installed {} filters",
        got.len()
    );
    assert!(
        differ.is_empty(),
        "{} line(s) differ:\n{}",
        differ.len(),
        differ.join("\n")
    );
    Ok(())
}
