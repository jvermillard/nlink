//! Every rule shape nlink can write must reconcile to an empty diff.
//!
//! The declarative diff byte-compares a declared rule against the kernel's
//! echo of it (after `normalize_tlv`, which reorders but cannot add). So
//! every attribute the kernel always dumps has to be in what nlink writes,
//! and nothing the kernel drops may be. A writer that gets this wrong
//! installs fine and then has its rule replaced on every apply, forever —
//! visible only to a second `diff()`.
//!
//! `reconcile_idempotent_reapply_yields_empty_diff` only ever declared
//! `match_tcp_dport` rules, so the masquerade nest (#362) and the lookup /
//! limit / log / reject writers were never in an `is_empty()` assertion.
//! This file declares one keyed rule per `Rule` helper and `Expr` writer
//! arm instead.

use std::net::{Ipv4Addr, Ipv6Addr};

use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::types::{
    ChainName, ChainType, CtState, Family, Hook, LimitUnit, Priority, SetKeyType, TcpFlags,
};
use nlink::netlink::nftables::{
    CmpOp, Expr, LogExpr, LookupExpr, MetaKey, NFT_REJECT_TCP_RST, PayloadBase, Register, Verdict,
};
use nlink::netlink::{Connection, Nftables};
use nlink::TcHandle;

use crate::common::converge::converges;
use crate::common::{TestNamespace, with_timeout};

/// Apply `cfg`; the diffs after it, and a second apply, must all be empty.
async fn assert_reconciles(conn: &Connection<Nftables>, cfg: &NftablesConfig) -> nlink::Result<()> {
    if let Err(why) = converges(conn, cfg, false).await {
        panic!(
            "every rule here was written by nlink and echoed by the kernel \
             unchanged, so nothing may be left to do after an apply. A rule \
             the diff lists is one whose writer disagrees with the kernel's \
             dump: {why}"
        );
    }
    Ok(())
}

/// Matchers, verdicts and statements in a filter chain.
#[tokio::test]
async fn every_filter_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit", "nft_log", "nft_reject_inet", "nft_ct");

    let ns = TestNamespace::new("nft-echo-filter")?;
    let conn = ns.connection_for::<Nftables>()?;

    let v4: Ipv4Addr = "192.0.2.0".parse().unwrap();
    let v6: Ipv6Addr = "2001:db8::".parse().unwrap();

    with_timeout(async {
        let cfg = NftablesConfig::new().table("shapes", Family::Inet, |t| {
            t.chain("input", |c| {
                c.hook(Hook::Input)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
            })
            .chain("sub", |c| c)
            .chain("forward", |c| {
                c.hook(Hook::Forward)
                    .priority(Priority::Mangle)
                    .chain_type(ChainType::Filter)
            })
            .set("allow4", |s| s.key_type(SetKeyType::Ipv4Addr).ipv4(v4))
            // Transport matchers.
            .rule_keyed("input", "tcp-dport", |r| r.match_tcp_dport(22).accept())
            .rule_keyed("input", "udp-dport", |r| r.match_udp_dport(53).accept())
            .rule_keyed("input", "tcp-sport", |r| r.match_tcp_sport(1024).accept())
            .rule_keyed("input", "udp-sport", |r| r.match_udp_sport(1024).accept())
            .rule_keyed("input", "tcp-dport-not", |r| r.match_tcp_dport_not(22).drop())
            .rule_keyed("input", "udp-dport-not", |r| r.match_udp_dport_not(53).drop())
            .rule_keyed("input", "l4proto", |r| r.match_l4proto(17).accept())
            .rule_keyed("input", "icmp", |r| r.match_icmp_type(8).accept())
            .rule_keyed("input", "icmpv6", |r| r.match_icmpv6_type(128).accept())
            .rule_keyed("input", "tcp-flags", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .accept()
            })
            // Address matchers, exact and prefix, plain and negated.
            .rule_keyed("input", "saddr4", |r| r.match_saddr_v4(v4, 24).accept())
            .rule_keyed("input", "daddr4", |r| r.match_daddr_v4(v4, 32).accept())
            .rule_keyed("input", "saddr6", |r| r.match_saddr_v6(v6, 64).accept())
            .rule_keyed("input", "daddr6", |r| r.match_daddr_v6(v6, 128).accept())
            .rule_keyed("input", "saddr4-not", |r| r.match_saddr_v4_not(v4, 24).drop())
            .rule_keyed("input", "daddr4-not", |r| r.match_daddr_v4_not(v4, 32).drop())
            .rule_keyed("input", "saddr6-not", |r| r.match_saddr_v6_not(v6, 64).drop())
            .rule_keyed("input", "daddr6-not", |r| r.match_daddr_v6_not(v6, 128).drop())
            // Set lookups.
            .rule_keyed("input", "saddr-in-set", |r| {
                r.match_saddr_in_set("allow4").accept()
            })
            .rule_keyed("input", "daddr-in-set", |r| {
                r.match_daddr_in_set("allow4").accept()
            })
            // `ip saddr != @allow4`: NFT_LOOKUP_F_INV round-trips.
            .rule_keyed("input", "saddr-not-in-set", |r| {
                r.expressions(vec![
                    Expr::Meta {
                        dreg: Register::R0,
                        key: MetaKey::NfProto,
                    },
                    Expr::Cmp {
                        sreg: Register::R0,
                        op: CmpOp::Eq,
                        data: vec![2],
                    },
                    Expr::Payload {
                        dreg: Register::R0,
                        base: PayloadBase::Network,
                        offset: 12,
                        len: 4,
                    },
                    LookupExpr::new("allow4", Register::R0).invert().into(),
                ])
                .drop()
            })
            // Meta / conntrack.
            .rule_keyed("input", "iif", |r| r.match_iif("lo").accept())
            .rule_keyed("input", "oif", |r| r.match_oif("lo").accept())
            .rule_keyed("input", "mark", |r| r.match_mark(0x10).accept())
            .rule_keyed("input", "ct-state", |r| {
                r.match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
                    .accept()
            })
            // Statements.
            .rule_keyed("input", "counter", |r| r.match_tcp_dport(80).counter())
            .rule_keyed("input", "limit", |r| {
                r.match_tcp_dport(81).limit(10, LimitUnit::Second).accept()
            })
            .rule_keyed("input", "log-prefix", |r| {
                r.match_tcp_dport(82).log(Some("nlink: "))
            })
            .rule_keyed("input", "log-bare", |r| r.match_tcp_dport(83).log(None))
            .rule_keyed("input", "log-group", |r| {
                r.expr(LogExpr::new().prefix("nlink-group: ").group(5))
            })
            .rule_keyed("input", "set-mark", |r| r.match_tcp_dport(84).set_mark(1))
            .rule_keyed("input", "set-mark-masked", |r| {
                r.match_tcp_dport(89).set_mark_masked(0x10, 0xff)
            })
            .rule_keyed("input", "mark-masked", |r| {
                r.match_mark_masked(0x10, 0xff).accept()
            })
            .rule_keyed("input", "set-priority", |r| {
                r.match_tcp_dport(90).set_priority(TcHandle::new(1, 0x10))
            })
            .rule_keyed("input", "set-ct-mark", |r| r.match_tcp_dport(91).set_ct_mark(7))
            .rule_keyed("input", "ct-mark", |r| r.match_ct_mark(7).accept())
            .rule_keyed("input", "save-mark", |r| r.match_tcp_dport(92).save_mark_to_ct())
            .rule_keyed("input", "restore-mark", |r| {
                r.match_tcp_dport(93).restore_mark_from_ct()
            })
            // `rt tcpmss` is only valid in forward/output/postrouting.
            .rule_keyed("forward", "mss-pmtu", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss_to_pmtu()
            })
            .rule_keyed("input", "mss", |r| {
                r.match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)
                    .clamp_tcp_mss(1360)
            })
            // Verdicts.
            .rule_keyed("input", "reject", |r| r.match_tcp_dport(85).reject())
            .rule_keyed("input", "reject-rst", |r| {
                r.match_tcp_dport(86).reject_with(NFT_REJECT_TCP_RST, 0)
            })
            .rule_keyed("input", "jump", |r| {
                r.match_tcp_dport(87).jump(ChainName::new("sub").unwrap())
            })
            .rule_keyed("input", "goto", |r| {
                r.match_tcp_dport(88).goto(ChainName::new("sub").unwrap())
            })
            .rule_keyed("sub", "return", |r| {
                r.expressions(vec![Expr::Verdict(Verdict::Return)])
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// #480: every reject form, in `ip`, `ip6` and `inet` tables. In `ip` and
/// `ip6` nlink sends `reject()` as the family's ICMP code, not ICMPX; the
/// diff renders it the same way, or a declared reject would never converge.
/// Interface-name matches — exact, `!=`, and nft's `"prefix*"` — install
/// as nft writes them and reconcile. A name over 15 bytes was cut to 15,
/// which no interface has, so the rule never matched; it is an error now
/// (#484).
#[tokio::test]
async fn interface_name_matches_are_what_nft_writes() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-echo-ifname")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("ifn", |c| {
                c.hook(Hook::Forward)
                    .priority(Priority::Filter)
                    .chain_type(ChainType::Filter)
            })
            .rule_keyed("ifn", "iif", |r| r.match_iif("d0").accept())
            .rule_keyed("ifn", "iif-not", |r| r.match_iif_not("d0").drop())
            .rule_keyed("ifn", "iif-prefix", |r| r.match_iif_prefix("veth").accept())
            .rule_keyed("ifn", "oif-not", |r| r.match_oif_not("d1").accept())
            .rule_keyed("ifn", "oif-prefix", |r| r.match_oif_prefix("br").accept())
        });
        assert_reconciles(&conn, &cfg).await?;
        let shown = ns.exec("nft", &["list", "chain", "inet", "t", "ifn"])?;
        for line in [
            "iifname \"d0\" accept",
            "iifname != \"d0\" drop",
            "iifname \"veth*\" accept",
            "oifname != \"d1\" accept",
            "oifname \"br*\" accept",
        ] {
            assert!(shown.contains(line), "nft does not show `{line}`:\n{shown}");
        }

        let long = NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("ifn", |c| c)
                .rule("ifn", |r| r.match_iif("a-sixteen-byte-n").accept())
        });
        let err = long
            .diff(&conn)
            .await
            .expect_err("a 16-byte interface name");
        assert!(err.to_string().contains("longer than 15 bytes"), "{err}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reject_rules_reconcile_in_every_family() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "nft_reject_inet"
    );

    let ns = TestNamespace::new("nft-echo-reject")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let mut cfg = NftablesConfig::new();
        for (name, family) in [
            ("r4", Family::Ip),
            ("r6", Family::Ip6),
            ("rx", Family::Inet),
        ] {
            cfg = cfg.table(name, family, |t| {
                let t = t
                    .chain("input", |c| c.hook(Hook::Input).priority(Priority::Filter))
                    .rule_keyed("input", "reject", |r| r.match_tcp_dport(85).reject())
                    .rule_keyed("input", "rst", |r| r.reject_tcp_reset())
                    .rule_keyed("input", "rst-after-dport", |r| {
                        r.match_tcp_dport(86).reject_tcp_reset()
                    });
                match family {
                    Family::Ip => t.rule_keyed("input", "icmp", |r| r.reject_icmp(13)),
                    Family::Ip6 => t.rule_keyed("input", "icmpv6", |r| r.reject_icmpv6(1)),
                    _ => t
                        .rule_keyed("input", "icmp", |r| r.reject_icmp(13))
                        .rule_keyed("input", "icmpv6", |r| r.reject_icmpv6(1)),
                }
            });
        }
        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// NAT statements, which need `nat`-type chains.
#[tokio::test]
async fn every_nat_rule_shape_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir");

    let ns = TestNamespace::new("nft-echo-nat")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("nat_shapes", Family::Inet, |t| {
            t.chain("postrouting", |c| {
                c.hook(Hook::Postrouting)
                    .priority(Priority::SrcNat)
                    .chain_type(ChainType::Nat)
            })
            .chain("prerouting", |c| {
                c.hook(Hook::Prerouting)
                    .priority(Priority::DstNat)
                    .chain_type(ChainType::Nat)
            })
            .rule_keyed("postrouting", "masq", |r| {
                r.match_saddr_v4("10.0.0.0".parse().unwrap(), 8).masquerade()
            })
            .rule_keyed("postrouting", "snat", |r| {
                r.match_saddr_v4("10.1.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), None)
            })
            .rule_keyed("postrouting", "snat-port", |r| {
                r.match_saddr_v4("10.2.0.0".parse().unwrap(), 16)
                    .snat("192.0.2.1".parse().unwrap(), Some(4000))
            })
            .rule_keyed("postrouting", "snat6", |r| {
                r.match_saddr_v6("fd00::".parse().unwrap(), 64)
                    .snat_v6("2001:db8::1".parse().unwrap(), None)
            })
            .rule_keyed("prerouting", "dnat", |r| {
                r.match_tcp_dport(8080)
                    .dnat("192.0.2.2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "dnat6", |r| {
                r.match_tcp_dport(8081)
                    .dnat_v6("2001:db8::2".parse().unwrap(), Some(80))
            })
            .rule_keyed("prerouting", "redir", |r| {
                r.match_tcp_dport(8082).redirect(None)
            })
            .rule_keyed("prerouting", "redir-port", |r| {
                r.match_tcp_dport(8083).redirect(Some(3128))
            })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// `flow add @ft` against a declared flowtable.
#[tokio::test]
async fn flow_offload_rule_installs_and_reconciles() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table", "nft_flow_offload");

    let ns = TestNamespace::new("nft-echo-flow")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        let cfg = NftablesConfig::new().table("flow", Family::Inet, |t| {
            t.flowtable("ft", |f| f)
                .chain("forward", |c| {
                    c.hook(Hook::Forward)
                        .priority(Priority::Filter)
                        .chain_type(ChainType::Filter)
                })
                .rule_keyed("forward", "offload", |r| {
                    r.match_ct_state(CtState::ESTABLISHED).flow_offload("ft")
                })
        });

        assert_reconciles(&conn, &cfg).await
    })
    .await
}

/// #528: NAT with address and port ranges and flags — what nlink-lab's
/// firewall writes as `dnat … to 10.0.1.10:8000-8999` and `masquerade
/// random` — reconciles, and `nft` lists each statement as written.
#[tokio::test]
async fn nat_ranges_and_flags_reconcile_and_list_as_nft_writes_them() -> nlink::Result<()> {
    use nlink::netlink::nftables::NatStatement;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat", "nft_masq", "nft_redir");

    let ns = TestNamespace::new("nft-echo-natrange")?;
    let conn = ns.connection_for::<Nftables>()?;
    let ip = |s: &str| -> std::net::IpAddr { s.parse().unwrap() };

    with_timeout(async {
        let cfg = NftablesConfig::new().table("natr", Family::Inet, |t| {
            t.chain("post", |c| {
                c.hook(Hook::Postrouting).priority(Priority::SrcNat).chain_type(ChainType::Nat)
            })
            .chain("pre", |c| {
                c.hook(Hook::Prerouting).priority(Priority::DstNat).chain_type(ChainType::Nat)
            })
            .rule_keyed("post", "snat-range", |r| {
                r.match_tcp_dport(1).nat(
                    NatStatement::snat(ip("10.0.0.1"))
                        .to(ip("10.0.0.9"))
                        .ports(40000, 40010)
                        .fully_random()
                        .persistent(),
                )
            })
            .rule_keyed("post", "snat6-range", |r| {
                r.match_tcp_dport(2)
                    .nat(NatStatement::snat(ip("2001:db8::1")).to(ip("2001:db8::9")))
            })
            .rule_keyed("post", "netmap", |r| {
                r.match_tcp_dport(3)
                    .nat(NatStatement::snat(ip("10.9.0.0")).to(ip("10.9.0.255")).netmap())
            })
            .rule_keyed("post", "masq-ports", |r| {
                r.match_tcp_dport(4).nat(NatStatement::masquerade().ports(1024, 2048).random())
            })
            .rule_keyed("pre", "dnat-port", |r| {
                r.match_tcp_dport(5).nat(NatStatement::dnat_to_port(Family::Ip, 8080))
            })
            .rule_keyed("pre", "dnat-range", |r| {
                r.match_tcp_dport(6)
                    .nat(NatStatement::dnat(ip("10.0.1.10")).ports(8000, 8999))
            })
            .rule_keyed("pre", "redir-range", |r| {
                r.match_tcp_dport(7).nat(NatStatement::redirect().ports(3000, 3010))
            })
        });
        assert_reconciles(&conn, &cfg).await?;

        let listed = ns.exec("nft", &["list", "table", "inet", "natr"])?;
        for want in [
            "snat ip to 10.0.0.1-10.0.0.9:40000-40010",
            "fully-random",
            "persistent",
            "snat ip6 to 2001:db8::1-2001:db8::9",
            "netmap",
            "masquerade to :1024-2048 random",
            "dnat ip to :8080",
            "dnat ip to 10.0.1.10:8000-8999",
            "redirect to :3000-3010",
        ] {
            assert!(listed.contains(want), "nft does not list {want:?}:\n{listed}");
        }
        Ok(())
    })
    .await
}
