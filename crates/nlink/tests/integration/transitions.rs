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
        // A `flows` change recreates the qdisc (#596).
        .check(expect_qdisc(
            "fq_codel",
            // In µs after codel's 2^-10 s round trip: 10 ms, 200 ms.
            &[
                ("limit", "2000"),
                ("flows", "1024"),
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
                // Half a second is 1 s, not 0, which is "off" (#597).
                q(|q| q.sfq().perturb(Duration::from_millis(500)).quantum(3028)),
            ],
        )
        .check(expect_qdisc(
            "sfq",
            &[("perturb", "1"), ("quantum", "3028")],
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
        // #515: a declared netem is a `NetemConfig`, so what has no builder
        // setter declares through `spec`, and leaving it out of the next
        // step takes it off: ECN and the slot go, the overheads go to 0,
        // and the seed — compared only when set — stays the kernel's.
        case(
            "netem-spec",
            vec![
                q(|q| {
                    use nlink::netlink::tc::{NetemConfig, NetemSlot};
                    q.spec(
                        NetemConfig::new()
                            .delay(Duration::from_millis(10))
                            .rate(nlink::Rate::mbit(1))
                            .rate_overhead(20, 53, 5)
                            .ecn(true)
                            .seed(7)
                            .slot(NetemSlot::new(
                                Duration::from_millis(1),
                                Duration::from_millis(2),
                            )),
                    )
                }),
                q(|q| {
                    q.spec(nlink::netlink::tc::NetemConfig::new().delay(Duration::from_millis(10)))
                }),
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

/// The edges of the inputs that take numbers and names. Each bad input is
/// refused before the kernel sees it, by the imperative call and by
/// `NetworkConfig::validate()` (#598).
#[tokio::test]
async fn boundaries() -> nlink::Result<()> {
    use nlink::netlink::link::{DummyLink, VlanLink};
    use nlink::netlink::tc::NetemConfig;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_netem");

    let ns = TestNamespace::new("boundaries")?;
    let conn = ns.connection()?;

    // Interface names: what the kernel's `dev_valid_name` refuses is
    // refused before the kernel (`à` is `C3 A0`, and 0xA0 is a space to
    // the kernel), and what it takes is created, a Unicode space included.
    for name in ["", ".", "..", "a/b", "a b", "a:b", "à0", "sixteen-bytes-xx"] {
        let err = conn.add_link(DummyLink::new(name)).await.expect_err(name);
        assert!(matches!(err, nlink::Error::Interface(_)), "{name:?}: {err}");
        let declared = NetworkConfig::new().link(name, |l| l.dummy());
        assert!(declared.validate().is_err(), "validate() took {name:?}");
    }
    conn.add_link(DummyLink::new("fifteen-bytes-x")).await?;
    conn.add_link(DummyLink::new("a\u{2003}b")).await?;
    conn.add_link(DummyLink::new("d0")).await?;

    // VLAN ids 0 (priority-tagged) and 4094 are VLANs; 4095 is refused
    // before the kernel's ERANGE.
    for id in [0u16, 4094] {
        let cfg = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .link(format!("v{id}").as_str(), move |l| l.vlan("d0", id));
        let applied = cfg.apply(&conn).await?;
        assert!(applied.is_success(), "vlan {id}: {applied:?}");
    }
    let err = conn
        .add_link(VlanLink::new("v4095", "d0", 4095))
        .await
        .expect_err("vlan 4095");
    assert!(err.errno().is_none(), "the kernel should not see it: {err}");
    let declared = NetworkConfig::new()
        .link("d0", |l| l.dummy())
        .link("v4095", |l| l.vlan("d0", 4095));
    assert!(declared.validate().is_err(), "validate() took vlan 4095");

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

    // Percentages clamp to 0..=100, and NaN is 0.
    assert_eq!(nlink::Percent::new(150.0).as_percent(), 100.0);
    assert_eq!(nlink::Percent::new(-5.0).as_percent(), 0.0);
    assert_eq!(nlink::Percent::new(f64::NAN).as_percent(), 0.0);

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
            nlink::EthProto::new(*proto_id),
            nlink::FilterPriority::new((i + 1) as u16),
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

// ============================================================================
// Offline prediction against the kernel
// ============================================================================

/// `diff_against` predicts, from declarations alone, the recreates a live
/// diff finds once the first config is applied: every certain prediction
/// is recreated, and nothing is recreated that was not at least a maybe
/// (#513).
#[tokio::test]
async fn offline_recreate_predictions_match_the_kernel() -> nlink::Result<()> {
    use nlink::netlink::config::{BondMode, Certainty, MacvlanMode};
    use nlink::netlink::link::VlanProtocol;
    use std::collections::BTreeSet;
    require_root!();
    nlink::require_modules!("dummy", "8021q", "vxlan", "bonding", "macvlan", "vrf");

    let base = || NetworkConfig::new().link("d0", |l| l.dummy().up());
    let cases: Vec<(&str, NetworkConfig, NetworkConfig)> = vec![
        (
            "vlan-id",
            base().link("v1", |l| l.vlan("d0", 10)),
            base().link("v1", |l| l.vlan("d0", 20)),
        ),
        (
            "vlan-protocol",
            base().link("v1", |l| l.vlan("d0", 10)),
            base().link("v1", |l| {
                l.vlan("d0", 10).vlan_protocol(VlanProtocol::Dot1ad)
            }),
        ),
        (
            "vxlan-vni-and-stacked-vlan",
            base()
                .link("vx0", |l| {
                    l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(4789)
                })
                .link("v1", |l| l.vlan("vx0", 5)),
            base()
                .link("vx0", |l| {
                    l.vxlan(200).vxlan_underlay_dev("d0").vxlan_port(4789)
                })
                .link("v1", |l| l.vlan("vx0", 5)),
        ),
        (
            "vxlan-port-from-default-to-another",
            base().link("vx0", |l| l.vxlan(100).vxlan_underlay_dev("d0")),
            base().link("vx0", |l| {
                l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(4789)
            }),
        ),
        (
            "vxlan-port-from-default-to-the-default",
            base().link("vx0", |l| l.vxlan(100).vxlan_underlay_dev("d0")),
            base().link("vx0", |l| {
                l.vxlan(100).vxlan_underlay_dev("d0").vxlan_port(8472)
            }),
        ),
        (
            "bond-mode",
            NetworkConfig::new().link("b0", |l| l.bond().bond_mode(BondMode::ActiveBackup)),
            NetworkConfig::new().link("b0", |l| l.bond().bond_mode(BondMode::BalanceRr)),
        ),
        (
            "macvlan-mode-changes-in-place",
            base().link("m0", |l| l.macvlan("d0").macvlan_mode(MacvlanMode::Bridge)),
            base().link("m0", |l| l.macvlan("d0").macvlan_mode(MacvlanMode::Private)),
        ),
        (
            "vrf-table",
            NetworkConfig::new().link("vrf0", |l| l.vrf(100)),
            NetworkConfig::new().link("vrf0", |l| l.vrf(200)),
        ),
        (
            "mtu-changes-in-place",
            base().link("v1", |l| l.vlan("d0", 10).mtu(1400)),
            base().link("v1", |l| l.vlan("d0", 10).mtu(1300)),
        ),
    ];
    let mut failures = Vec::new();
    for (name, before, after) in cases {
        let ns = TestNamespace::new(&format!("off-{}", &name[..name.len().min(8)]))?;
        let conn = ns.connection()?;
        let applied = before.apply(&conn).await?;
        assert!(applied.is_success(), "{name}: {applied:?}");
        let live: BTreeSet<String> = after
            .diff(&conn)
            .await?
            .links_to_recreate
            .into_iter()
            .map(|r| r.name)
            .collect();
        let offline = after.diff_against(&before);
        let certain: BTreeSet<String> = offline
            .recreates
            .iter()
            .filter(|r| r.certainty == Certainty::Certain)
            .map(|r| r.name.clone())
            .collect();
        let any: BTreeSet<String> = offline.recreates.iter().map(|r| r.name.clone()).collect();
        if !certain.is_subset(&live) || !live.is_subset(&any) {
            failures.push(format!(
                "{name}: live {live:?}, offline certain {certain:?}, offline any {any:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

/// A declared handle is the handle the kernel holds, a classful kind sits at
/// `1:` where its classes can name it, and the kernel's own root comes back
/// when declared. Each step converges (#514).
#[tokio::test]
async fn qdisc_handles_change_in_place() -> nlink::Result<()> {
    use nlink::TcHandle;
    use nlink::netlink::config::QdiscBuilder;
    require_root!();
    nlink::require_modules!("dummy", "sch_netem", "sch_prio");

    let q = |f: fn(QdiscBuilder) -> QdiscBuilder| dummy(|l| l).qdisc("d0", f);
    let steps = [
        q(|q| q.netem().handle(TcHandle::major_only(0x10))),
        q(|q| q.netem().handle(TcHandle::major_only(0x20))),
        q(|q| q.prio()),
        q(|q| q.kernel_default()),
    ];
    let want = ["netem 10:", "netem 20:", "prio 1:", "default"];
    let ns = TestNamespace::new("tr-handles")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let out = ns
            .exec("tc", &["-j", "qdisc", "show", "dev", "d0", "root"])
            .map_err(|e| e.to_string())?;
        let qdiscs: serde_json::Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        let root = &qdiscs[0];
        let shown = format!(
            "{} {}",
            root["kind"].as_str().unwrap_or("?"),
            root["handle"].as_str().unwrap_or("?")
        );
        let ok = match want[i] {
            // The kernel's default root has handle 0: — `noqueue` on a
            // dummy.
            "default" => root["handle"] == "0:",
            w => shown == w,
        };
        if ok {
            Ok(())
        } else {
            Err(format!("want {}, the kernel has {shown}: {out}", want[i]))
        }
    })
    .await
}

/// Address attributes changed A→B→none (#516): an IPv4 metric and label
/// (the label only a recreate changes), IPv6 flags and metric (changed in
/// place), lifetimes from finite to forever. Every step converges, and
/// `ip -j addr` shows what each declares.
#[tokio::test]
async fn address_attributes_change_in_place() -> nlink::Result<()> {
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("dummy");

    type Want = (Option<u64>, &'static str, bool, bool, bool);
    let step = |a: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder,
                b: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder,
                c: fn(nlink::netlink::config::AddressBuilder) -> nlink::netlink::config::AddressBuilder| {
        dummy(|l| l)
            .address_with("d0", "10.70.0.1/24", a)
            .and_then(|cfg| cfg.address_with("d0", "fd70::1/64", b))
            .and_then(|cfg| cfg.address_with("d0", "10.71.0.1/24", c))
            .expect("valid addresses")
    };
    let steps = [
        step(
            |a| a.metric(100).label("d0:a"),
            |a| a.nodad().metric(100),
            |a| a.lifetime(Duration::from_secs(3600), Duration::from_secs(1800)),
        ),
        step(
            |a| a.metric(200).label("d0:b"),
            |a| a.noprefixroute().metric(200),
            |a| a,
        ),
        step(|a| a, |a| a, |a| a),
    ];
    // (10.70 metric, 10.70 label, fd70 nodad, fd70 noprefixroute, 10.71 dynamic)
    let want: [Want; 3] = [
        (Some(100), "d0:a", true, false, true),
        (Some(200), "d0:b", false, true, false),
        (None, "d0", false, false, false),
    ];
    let ns = TestNamespace::new("tr-addr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let links = ip_json(&ns, &["addr", "show", "dev", "d0"])?;
        let info = links[0]["addr_info"].as_array().cloned().unwrap_or_default();
        let find = |local: &str| {
            info.iter()
                .find(|a| a["local"] == local)
                .cloned()
                .ok_or_else(|| format!("{local} missing: {info:?}"))
        };
        let (v4, v6, life) = (find("10.70.0.1")?, find("fd70::1")?, find("10.71.0.1")?);
        let flag = |a: &serde_json::Value, k: &str| a[k].as_bool().unwrap_or(false);
        let have: Want = (
            v4["metric"].as_u64(),
            if v4["label"] == "d0:a" { "d0:a" } else if v4["label"] == "d0:b" { "d0:b" } else { "d0" },
            flag(&v6, "nodad"),
            flag(&v6, "noprefixroute"),
            flag(&life, "dynamic"),
        );
        let fd70_metric = v6["metric"].as_u64();
        let want_fd70 = want[i].0;
        if have != want[i] || fd70_metric != want_fd70 {
            return Err(format!(
                "step {}: want {:?} (fd70 metric {want_fd70:?}), have {have:?} (fd70 metric {fd70_metric:?}): {info:?}",
                i + 1,
                want[i]
            ));
        }
        // One 10.70.0.1, whatever the label: a recreate, not a second one.
        let copies = info.iter().filter(|a| a["local"] == "10.70.0.1").count();
        if copies != 1 {
            return Err(format!("{copies} copies of 10.70.0.1"));
        }
        Ok(())
    })
    .await
}

/// Route attributes changed A→B→none (#516): source, on-link and metrics
/// for IPv4, source and metrics for IPv6. A replace drops what it is not
/// sent, so each step converges and `ip -j -d route` shows exactly what
/// it declares.
#[tokio::test]
async fn route_attributes_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    type RB = nlink::netlink::config::RouteBuilder;
    let step = |v4: fn(RB) -> RB, v6: fn(RB) -> RB| {
        dummy(|l| l)
            .address("d0", "10.80.0.1/24")
            .and_then(|c| c.address("d0", "10.80.0.9/24"))
            .expect("addresses")
            .address_with("d0", "fd80::1/64", |a| a.nodad())
            .and_then(|c| c.address_with("d0", "fd80::9/64", |a| a.nodad()))
            .expect("v6 addresses")
            .route("10.81.0.0/16", move |r| v4(r.via("10.80.0.2").dev("d0")))
            .and_then(|c| c.route("fd81::/64", move |r| v6(r.via("fd80::2").dev("d0"))))
            .expect("routes")
    };
    let steps = [
        step(
            |r| r.src("10.80.0.1").onlink().mtu(1400).advmss(1300),
            |r| r.src("fd80::1").hoplimit(10),
        ),
        step(
            |r| r.src("10.80.0.9").mtu(1500).initcwnd(10),
            |r| r.src("fd80::9").hoplimit(20).mtu(1280),
        ),
        step(|r| r, |r| r),
    ];
    // (prefsrc, onlink, metrics) as `ip -j -d route` shows them.
    let want: [[(&str, bool, &str); 2]; 3] = [
        [
            ("10.80.0.1", true, r#"[{"mtu":1400,"advmss":1300}]"#),
            ("fd80::1", false, r#"[{"hoplimit":10}]"#),
        ],
        [
            ("10.80.0.9", false, r#"[{"mtu":1500,"initcwnd":10}]"#),
            ("fd80::9", false, r#"[{"mtu":1280,"hoplimit":20}]"#),
        ],
        [("", false, "null"), ("", false, "null")],
    ];
    let ns = TestNamespace::new("tr-rtattr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        for (k, (family, dst)) in [("-4", "10.81.0.0/16"), ("-6", "fd81::/64")].into_iter().enumerate() {
            let routes = ip_json(&ns, &[family, "-d", "route", "show", dst])?;
            let r = &routes[0];
            let have = (
                r["prefsrc"].as_str().unwrap_or(""),
                r["flags"].as_array().is_some_and(|f| f.iter().any(|x| x == "onlink")),
                r["metrics"].clone(),
            );
            let (src, onlink, metrics) = want[i][k];
            let metrics: serde_json::Value = serde_json::from_str(metrics).expect("json");
            if have != (src, onlink, metrics) {
                return Err(format!("{dst} step {}: want {:?}, have {have:?}: {r}", i + 1, want[i][k]));
            }
        }
        Ok(())
    })
    .await
}

/// Link attributes changed A→B (#516): queue length, alias, group, the
/// GSO/GRO limits, promiscuous mode, alternative names, and protodown on a
/// vxlan (dummy and veth refuse it). A third step that declares none
/// leaves them as they are: an attribute not declared is not managed.
#[tokio::test]
async fn link_attributes_change_in_place() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "vxlan");

    struct Want {
        txqlen: u64,
        alias: &'static str,
        group: &'static str,
        gso: (u64, u64, u64),
        promisc: bool,
        altnames: &'static [&'static str],
        protodown: bool,
    }
    let declare = |w: Option<&Want>| {
        let mut cfg = NetworkConfig::new();
        cfg = match w {
            Some(w) => {
                let (size, segs, gro) = w.gso;
                cfg.link("d0", |l| {
                    let mut l = l
                        .dummy()
                        .txqlen(w.txqlen as u32)
                        .alias(w.alias)
                        .group(w.group.parse().unwrap())
                        .gso_max_size(size as u32)
                        .gso_max_segs(segs as u32)
                        .gro_max_size(gro as u32)
                        .promisc(w.promisc);
                    for a in w.altnames {
                        l = l.altname(a);
                    }
                    l
                })
                .link("vx0", |l| l.vxlan(42).vxlan_local(v4(10, 0, 0, 1)).protodown(w.protodown))
            }
            None => cfg
                .link("d0", |l| l.dummy())
                .link("vx0", |l| l.vxlan(42).vxlan_local(v4(10, 0, 0, 1))),
        };
        cfg
    };
    let a = Want {
        txqlen: 500,
        alias: "lab-a",
        group: "7",
        gso: (32000, 50, 32000),
        promisc: true,
        altnames: &["d0-a", "d0-b"],
        protodown: true,
    };
    let b = Want {
        txqlen: 1000,
        alias: "lab-b",
        group: "9",
        gso: (16000, 20, 16000),
        promisc: false,
        altnames: &["d0-b", "d0-c"],
        protodown: false,
    };
    let steps = [declare(Some(&a)), declare(Some(&b)), declare(None)];
    let ns = TestNamespace::new("tr-linkattr")?;
    crate::common::converge::assert_transition(&ns, &steps, false, async |i, _conn| {
        let w = if i == 0 { &a } else { &b };
        let d0 = &ip_json(&ns, &["-d", "link", "show", "d0"])?[0];
        let vx0 = &ip_json(&ns, &["-d", "link", "show", "vx0"])?[0];
        let flags: Vec<&str> = d0["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).collect();
        let mut altnames: Vec<&str> = d0["altnames"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).collect();
        altnames.sort();
        let have = (
            d0["txqlen"].as_u64(),
            d0["ifalias"].as_str(),
            d0["group"].as_str(),
            (d0["gso_max_size"].as_u64(), d0["gso_max_segs"].as_u64(), d0["gro_max_size"].as_u64()),
            flags.contains(&"PROMISC"),
            altnames.clone(),
            vx0["proto_down"].as_bool().unwrap_or(false),
        );
        let want = (
            Some(w.txqlen),
            Some(w.alias),
            Some(w.group),
            (Some(w.gso.0), Some(w.gso.1), Some(w.gso.2)),
            w.promisc,
            w.altnames.to_vec(),
            w.protodown,
        );
        if have != want {
            return Err(format!("step {}: want {want:?}, have {have:?}", i + 1));
        }
        Ok(())
    })
    .await
}
