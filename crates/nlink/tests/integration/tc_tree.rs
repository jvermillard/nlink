//! Declared TC trees (#514): classes, leaf qdiscs and filters under
//! `NetworkConfig::tc`, changed in place, removed, put back after a
//! recreate, and an IFB redirect checked with traffic.

use std::net::SocketAddr;

use nlink::netlink::config::{ApplyOptions, NetworkConfig, QdiscBuilder};
use nlink::netlink::filter::{FlowerFilter, MatchallFilter};
use nlink::netlink::tc::{FqCodelConfig, HtbClassConfig, SfqConfig};
use nlink::{EthProto, FilterPriority, Percent, Rate, TcHandle};

use crate::common::TestNamespace;
use crate::common::converge::assert_transition;
use crate::common::topo::NsPair;
use crate::common::traffic::deliver_udp;
use crate::common::with_timeout;

fn h(major: u16, minor: u16) -> TcHandle {
    TcHandle::new(major, minor)
}

/// `tc -j <what> show dev <dev> [extra]` inside `ns`, parsed.
fn tc_json(ns: &TestNamespace, what: &str, dev: &str, extra: &[&str]) -> Result<serde_json::Value, String> {
    let mut args = vec!["-j", what, "show", "dev", dev];
    args.extend_from_slice(extra);
    let out = ns.exec("tc", &args).map_err(|e| e.to_string())?;
    serde_json::from_str(&out).map_err(|e| format!("{e}: {out}"))
}

/// The class handles `tc class show` lists on `dev`, sorted.
fn class_handles(ns: &TestNamespace, dev: &str) -> Result<Vec<String>, String> {
    let classes = tc_json(ns, "class", dev, &[])?;
    let mut handles: Vec<String> = classes
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["handle"].as_str().map(str::to_string))
        .collect();
    handles.sort();
    Ok(handles)
}

/// `(priority, kind)` of each filter `tc filter show` lists at `parent`,
/// one per filter (the per-handle lines folded), sorted.
fn filters_at(ns: &TestNamespace, dev: &str, parent: &str) -> Result<Vec<(u64, String)>, String> {
    let filters = tc_json(ns, "filter", dev, &["parent", parent])?;
    let mut out: Vec<(u64, String)> = filters
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| Some((f["pref"].as_u64()?, f["kind"].as_str()?.to_string())))
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// The kind of the qdisc in class `class` on `dev`, if any.
fn leaf_kind(ns: &TestNamespace, dev: &str, class: &str) -> Result<Option<String>, String> {
    let qdiscs = tc_json(ns, "qdisc", dev, &[])?;
    Ok(qdiscs
        .as_array()
        .into_iter()
        .flatten()
        .find(|q| q["parent"].as_str() == Some(class))
        .and_then(|q| q["kind"].as_str().map(str::to_string)))
}

fn shaped(f: impl FnOnce(nlink::netlink::config::TcBuilder) -> nlink::netlink::config::TcBuilder) -> NetworkConfig {
    NetworkConfig::new()
        .link("d0", |l| l.dummy().up())
        .qdisc("d0", |q: QdiscBuilder| q.htb().default_class(0x20))
        .tc("d0", f)
}

fn ssh_to(port: u16, class: TcHandle) -> FlowerFilter {
    FlowerFilter::new().ip_proto_tcp().dst_port(port).classid(class)
}

/// A tree changed A→B in place, then cut down: each step converges, and
/// `tc` shows what each declares — a class's rate changed, a filter's key
/// changed, a leaf swapped for another kind, and what the last step drops
/// gone from the kernel.
#[tokio::test]
async fn a_tree_changes_in_place_and_drops_what_it_no_longer_declares() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!(
        "dummy",
        "sch_htb",
        "sch_fq_codel",
        "sch_sfq",
        "cls_flower",
        "cls_matchall"
    );

    let steps = [
        shaped(|t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(100)))
                .class(h(1, 1), h(1, 0x10), HtbClassConfig::new(Rate::mbit(60)).ceil(Rate::mbit(100)))
                .class(h(1, 1), h(1, 0x20), HtbClassConfig::new(Rate::mbit(40)))
                .leaf(h(1, 0x10), h(0x10, 0), FqCodelConfig::new())
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh_to(22, h(1, 0x10)))
                .filter(
                    h(1, 0),
                    FilterPriority::new(2),
                    EthProto::IP,
                    MatchallFilter::new().classid(h(1, 0x20)),
                )
        }),
        shaped(|t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(100)))
                .class(h(1, 1), h(1, 0x10), HtbClassConfig::new(Rate::mbit(30)).ceil(Rate::mbit(100)))
                .class(h(1, 1), h(1, 0x20), HtbClassConfig::new(Rate::mbit(40)))
                .class(h(1, 1), h(1, 0x30), HtbClassConfig::new(Rate::mbit(20)))
                .leaf(h(1, 0x10), h(0x10, 0), SfqConfig::new())
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh_to(80, h(1, 0x10)))
                .filter(
                    h(1, 0),
                    FilterPriority::new(2),
                    EthProto::IP,
                    MatchallFilter::new().classid(h(1, 0x30)),
                )
        }),
        shaped(|t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(100)))
                .class(h(1, 1), h(1, 0x10), HtbClassConfig::new(Rate::mbit(30)).ceil(Rate::mbit(100)))
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh_to(80, h(1, 0x10)))
        }),
    ];
    let ns = TestNamespace::new("tt-tree")?;
    assert_transition(&ns, &steps, false, async |i, _conn| {
        let classes = class_handles(&ns, "d0")?;
        let filters = filters_at(&ns, "d0", "1:")?;
        let leaf = leaf_kind(&ns, "d0", "1:10")?;
        let want: (&[&str], &[(u64, &str)], Option<&str>) = match i {
            0 => (&["1:1", "1:10", "1:20"], &[(1, "flower"), (2, "matchall")], Some("fq_codel")),
            1 => (
                &["1:1", "1:10", "1:20", "1:30"],
                &[(1, "flower"), (2, "matchall")],
                Some("sfq"),
            ),
            _ => (&["1:1", "1:10"], &[(1, "flower")], None),
        };
        let want_filters: Vec<(u64, String)> =
            want.1.iter().map(|(p, k)| (*p, k.to_string())).collect();
        if classes != want.0 || filters != want_filters || leaf.as_deref() != want.2 {
            return Err(format!(
                "classes {classes:?} filters {filters:?} leaf {leaf:?}, want {want:?}"
            ));
        }
        // The values, not only the names: 1:10's rate and the flower's port.
        let rate = tc_json(&ns, "class", "d0", &["classid", "1:10"])?;
        let want_rate = if i == 0 { 7_500_000 } else { 3_750_000 };
        if rate[0]["rate"].as_u64() != Some(want_rate) {
            return Err(format!("1:10's rate: {rate}, want {want_rate} bytes/s"));
        }
        let flower = tc_json(&ns, "filter", "d0", &["parent", "1:", "pref", "1"])?;
        let port = if i == 0 { 22 } else { 80 };
        let shown = flower.to_string();
        if !shown.contains(&format!("\"dst_port\":{port}")) {
            return Err(format!("the flower should match port {port}: {shown}"));
        }
        Ok(())
    })
    .await
}

/// Everything `veth-b` receives, redirected to an IFB whose root drops it
/// all: nothing arrives. The next config drops the redirect, with the
/// first as its previous, and traffic flows again.
#[tokio::test]
async fn an_ifb_redirect_shapes_what_a_device_receives() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("veth", "ifb", "sch_ingress", "sch_netem", "cls_matchall", "act_mirred");

    let pair = NsPair::new("tt-ifb", 71).await?;
    with_timeout(async {
        let b = pair.b.connection()?;
        let dst = SocketAddr::new(pair.b_addr.into(), 9000);
        assert_eq!(deliver_udp(&pair.a, &pair.b, dst, 5), 5, "before the redirect");

        let ifb = || {
            NetworkConfig::new()
                .link("ifb0", |l| l.ifb().up())
                .qdisc("ifb0", |q| q.netem().loss_pct(Percent::new(100.0)))
                .qdisc(pair.b_if, |q| q.ingress())
        };
        let redirected = ifb().tc(pair.b_if, |t| t.redirect_ingress_to("ifb0"));
        let applied = redirected.apply(&b).await?;
        assert!(applied.is_success(), "{:?}", applied.errors);
        let diff = redirected.diff(&b).await?;
        assert!(diff.is_empty(), "the redirect does not converge:\n{diff}");

        assert_eq!(deliver_udp(&pair.a, &pair.b, dst, 5), 0, "redirected into a 100% loss");
        let netem = tc_json(&pair.b, "qdisc", "ifb0", &["root"]).map_err(nlink::Error::InvalidMessage)?;
        let shown = pair.b.exec("tc", &["-s", "-j", "qdisc", "show", "dev", "ifb0", "root"])?;
        let stats: serde_json::Value = serde_json::from_str(&shown).expect("tc -j");
        assert!(
            stats[0]["drops"].as_u64().unwrap_or(0) > 0,
            "the IFB's netem dropped nothing — was anything redirected? {netem} {shown}"
        );

        // Dropped from the config, with the one that declared it as the
        // previous: the redirect goes, the ingress qdisc stays.
        let plain = ifb();
        let applied = plain
            .apply_with_options(&b, ApplyOptions::default().with_previous(redirected))
            .await?;
        assert!(applied.is_success(), "{:?}", applied.errors);
        let filters = filters_at(&pair.b, pair.b_if, "ffff:").map_err(nlink::Error::InvalidMessage)?;
        assert!(filters.is_empty(), "the redirect should be gone: {filters:?}");
        assert_eq!(deliver_udp(&pair.a, &pair.b, dst, 5), 5, "the redirect is gone");
        Ok(())
    })
    .await
}

/// A VLAN whose id changes is deleted and created again, which takes its
/// classes and filters with it. Those were blockers, so the recreate was
/// refused; declared in its tree, the apply puts them back (#514).
#[tokio::test]
async fn a_recreated_link_gets_its_declared_tree_back() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "8021q", "sch_htb", "cls_flower");

    let vlan = |id: u16| {
        NetworkConfig::new()
            .link("d0", |l| l.dummy().up())
            .link("v0", move |l| l.vlan("d0", id).up())
            .qdisc("v0", |q| q.htb().default_class(0x10))
            .tc("v0", |t| {
                t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(10)))
                    .class(h(1, 1), h(1, 0x10), HtbClassConfig::new(Rate::mbit(5)))
                    .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh_to(22, h(1, 0x10)))
            })
    };
    let ns = TestNamespace::new("tt-recreate")?;
    assert_transition(&ns, &[vlan(10), vlan(20)], false, async |i, _conn| {
        let link = crate::common::converge::ip_json(&ns, &["-d", "link", "show", "v0"])?;
        let id = link[0]["linkinfo"]["info_data"]["id"].as_u64();
        let want_id = if i == 0 { 10 } else { 20 };
        if id != Some(want_id) {
            return Err(format!("v0's id is {id:?}, want {want_id}"));
        }
        let classes = class_handles(&ns, "v0")?;
        let filters = filters_at(&ns, "v0", "1:")?;
        if classes != ["1:1", "1:10"] || filters != [(1, "flower".to_string())] {
            return Err(format!("classes {classes:?}, filters {filters:?}"));
        }
        Ok(())
    })
    .await
}
