//! The apply as a list of steps (#518).
//!
//! [`ConfigDiff::plan`](super::ConfigDiff::plan) turns a diff into a
//! [`Plan`]: every kernel call the apply makes, in the order it makes
//! them, including the ones a diff only implies — an MTU raised before a
//! link stacked on it is created, a bridge MTU pinned again after its
//! ports moved it, a VLAN taken down again after its lower device came up,
//! an old IPv6 prefix removed right before the address is added at the new
//! one. The apply *is* the plan: [`Plan::apply`] runs `steps` in order, and
//! [`ConfigDiff::apply`](super::ConfigDiff::apply) is `plan().apply()`, so
//! what is printed is what runs.
//!
//! Each step that changed something is recorded in
//! [`ApplyResult::journal`](super::ApplyResult::journal) with its
//! [`inverse`](Step::inverse) where one can be known, and
//! [`ApplyResult::undo`](super::ApplyResult::undo) is the plan that puts
//! those back.

use std::fmt;

use super::{
    DeclaredAddress, DeclaredLink, DeclaredQdisc, DeclaredRoute, LinkChanges, LinkRecreate,
    LinkRemoval, RouteConflict,
    diff::route_text,
    tc_tree::DeclaredTc,
};
use crate::netlink::types::route::RouteProtocol;

/// One kernel change of an apply, or a refusal that stops it (#518).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "step"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Step {
    /// A declared link that does not exist, and that nothing in the plan
    /// creates (#475): the apply fails here.
    MissingLink {
        /// The link.
        name: String,
    },
    /// A declared route whose place holds a route the config does not own
    /// (#469): the apply fails here rather than replace it.
    RefuseRoute(RouteConflict),
    /// A link the previous config declared, whose deletion would destroy
    /// what no config declares (#512): the apply fails here.
    RefuseRemoval(LinkRemoval),
    /// A link whose recreate would destroy what the config does not
    /// declare (#417): the apply fails here.
    RefuseRecreate(LinkRecreate),
    /// Delete a link to create it again: a kind parameter it cannot change
    /// live (#417). The create is a later step.
    DeleteForRecreate(LinkRecreate),
    /// Delete a link the previous config declared and this one does not
    /// (#512).
    RemoveLink(LinkRemoval),
    /// Delete a link: the inverse of [`Self::CreateLink`].
    DeleteLink {
        /// The link.
        name: String,
    },
    /// Raise a link's MTU before a link stacked on it is created: the
    /// kernel refuses an MTU above the lower device's at create (#473).
    RaiseMtuFirst {
        /// The lower link.
        link: String,
        /// Its declared MTU.
        mtu: u32,
    },
    /// Create a declared link.
    CreateLink(DeclaredLink),
    /// Change a link in place: state, MTU, master, MAC, kind parameters.
    ModifyLink {
        /// The link.
        name: String,
        /// What changes.
        changes: LinkChanges,
        /// The MTU was set by an earlier [`Self::RaiseMtuFirst`].
        mtu_already_set: bool,
    },
    /// Set a bridge's declared MTU again if the port changes before moved
    /// it (`br_mtu_auto_adjust`). Not counted as a change of its own.
    PinBridgeMtu {
        /// The bridge.
        bridge: String,
        /// Its declared MTU.
        mtu: u32,
    },
    /// Take a declared-down VLAN down again if its lower device came up
    /// before (`vlan_device_event`, #436). Not counted as a change of its
    /// own.
    HoldVlanDown {
        /// The VLAN.
        vlan: String,
    },
    /// Add a declared address.
    AddAddress(DeclaredAddress),
    /// Delete an address.
    DeleteAddress {
        /// The address.
        address: DeclaredAddress,
        /// Why, when it is not a purge: the IPv6 address re-added next at
        /// another prefix, which the kernel knows by address alone (#461).
        reason: Option<String>,
    },
    /// Install a route with `NLM_F_REPLACE`: added, or overwriting the one
    /// in its place.
    ReplaceRoute {
        /// The route it overwrites, if one is there.
        before: Option<DeclaredRoute>,
        /// The route installed.
        after: DeclaredRoute,
    },
    /// Delete a route.
    DeleteRoute(DeclaredRoute),
    /// Delete a qdisc the previous config declared; the kernel's default
    /// comes back (#512).
    DeleteQdisc(DeclaredQdisc),
    /// Replace a qdisc with the declared one.
    ReplaceQdisc(DeclaredQdisc),
    /// Add a declared qdisc.
    AddQdisc(DeclaredQdisc),
    /// Diff a declared TC tree again, against the device as the steps
    /// before left it, and apply the difference (#514).
    TcTree {
        /// The device.
        dev: String,
        /// What the diff found, one line each; the apply diffs again.
        planned: Vec<String>,
        #[cfg_attr(feature = "serde", serde(skip))]
        #[cfg_attr(feature = "schemars", schemars(skip))]
        tree: Box<DeclaredTc>,
        #[cfg_attr(feature = "serde", serde(skip))]
        #[cfg_attr(feature = "schemars", schemars(skip))]
        previous: Option<Box<DeclaredTc>>,
    },
}

impl Step {
    /// Whether the apply fails at this step.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::MissingLink { .. }
                | Self::RefuseRoute(_)
                | Self::RefuseRemoval(_)
                | Self::RefuseRecreate(_)
        )
    }

    /// The step that undoes this one, when it can be known from the plan:
    /// an address or route added or removed, a link created, a qdisc the
    /// previous config declared, a link's state, MTU, master or MAC.
    ///
    /// `None` for what cannot be put back from the plan alone: a deleted
    /// link and everything that went with it, a kind parameter, a replaced
    /// qdisc's old parameters, a TC tree, a refusal.
    pub fn inverse(&self) -> Option<Step> {
        Some(match self {
            Self::CreateLink(link) => Self::DeleteLink {
                name: link.name.clone(),
            },
            Self::ModifyLink { name, changes, .. } => Self::ModifyLink {
                name: name.clone(),
                changes: invert_link_changes(changes)?,
                mtu_already_set: false,
            },
            Self::AddAddress(address) => Self::DeleteAddress {
                address: address.clone(),
                reason: None,
            },
            Self::DeleteAddress { address, .. } => Self::AddAddress(address.clone()),
            Self::ReplaceRoute { before, after } => match before {
                Some(before) => Self::ReplaceRoute {
                    before: Some(after.clone()),
                    after: before.clone(),
                },
                None => Self::DeleteRoute(after.clone()),
            },
            Self::DeleteRoute(route) => Self::ReplaceRoute {
                before: None,
                after: route.clone(),
            },
            Self::AddQdisc(q) => Self::DeleteQdisc(q.clone()),
            Self::DeleteQdisc(q) => Self::AddQdisc(q.clone()),
            _ => return None,
        })
    }

    /// Why the step is in the plan, where the plan knows more than its
    /// kind says.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::DeleteForRecreate(r) => Some(r.reason.clone()),
            Self::RemoveLink(_) => Some("the previous config declared it".into()),
            Self::RaiseMtuFirst { .. } => {
                Some("a link created on it needs the MTU at create".into())
            }
            Self::PinBridgeMtu { .. } => {
                Some("ports joining or leaving move a bridge's MTU".into())
            }
            Self::HoldVlanDown { .. } => {
                Some("a lower device coming up brings its VLANs up".into())
            }
            Self::DeleteAddress { reason, .. } => reason.clone(),
            Self::ReplaceRoute {
                before: Some(before),
                ..
            } => Some(format!("replaces {}", route_text(before))),
            _ => None,
        }
    }

    /// Whether the step is a kernel side effect the plan corrects, rather
    /// than a change of its own: not counted, and skipped in a dry run.
    pub(crate) fn is_consequence(&self) -> bool {
        matches!(
            self,
            Self::RaiseMtuFirst { .. } | Self::PinBridgeMtu { .. } | Self::HoldVlanDown { .. }
        )
    }
}

/// The inverse of a link change, from what the link had; `None` for a
/// kind-parameter change, or a link this apply creates.
fn invert_link_changes(changes: &LinkChanges) -> Option<LinkChanges> {
    if changes.kind_update.is_some() {
        return None;
    }
    let was = changes.was.as_ref()?;
    let master_moved = changes.set_master.is_some() || changes.unset_master;
    Some(LinkChanges {
        set_up: changes.set_down && was.up,
        set_down: changes.set_up && !was.up,
        set_mtu: changes.set_mtu.and(was.mtu),
        set_master: if master_moved { was.master.clone() } else { None },
        unset_master: master_moved && was.master.is_none(),
        set_address: changes.set_address.and(was.address),
        ..LinkChanges::default()
    })
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLink { name } => write!(
                f,
                "! link {name} (missing: it does not exist, and the config does not create it)"
            ),
            Self::RefuseRoute(conflict) => write!(f, "{conflict}"),
            Self::RefuseRemoval(removal) => write!(f, "{removal}"),
            Self::RefuseRecreate(recreate) => write!(f, "{recreate}"),
            Self::DeleteForRecreate(recreate) => write!(
                f,
                "- link {} (to recreate it: {})",
                recreate.name, recreate.reason
            ),
            Self::RemoveLink(removal) => write!(f, "{removal}"),
            Self::DeleteLink { name } => write!(f, "- link {name}"),
            Self::RaiseMtuFirst { link, mtu } => {
                write!(f, "~ link {link} mtu {mtu} (before the links created on it)")
            }
            Self::CreateLink(link) => write!(
                f,
                "+ link {} ({})",
                link.name,
                link.link_type.kind().unwrap_or("physical")
            ),
            Self::ModifyLink { name, changes, .. } => {
                write!(f, "~ link {name} ({})", changes.summary())
            }
            Self::PinBridgeMtu { bridge, mtu } => {
                write!(f, "~ link {bridge} mtu {mtu} (if its ports moved it)")
            }
            Self::HoldVlanDown { vlan } => {
                write!(f, "~ link {vlan} down (if its lower device brought it up)")
            }
            Self::AddAddress(a) => {
                write!(f, "+ address {}/{} on {}", a.address, a.prefix_len, a.dev)
            }
            Self::DeleteAddress { address: a, .. } => {
                write!(f, "- address {}/{} on {}", a.address, a.prefix_len, a.dev)
            }
            Self::ReplaceRoute { before, after } => match before {
                Some(before) => write!(
                    f,
                    "~ route {} (replacing {})",
                    route_text(after),
                    route_text(before)
                ),
                None => write!(f, "+ route {}", route_text(after)),
            },
            Self::DeleteRoute(route) => write!(f, "- route {}", route_text(route)),
            Self::DeleteQdisc(q) => write!(
                f,
                "- qdisc {} on {} ({:?})",
                q.qdisc_type.kind(),
                q.dev,
                q.effective_parent()
            ),
            Self::ReplaceQdisc(q) => {
                write!(f, "~ qdisc {} on {} ({:?})", q.qdisc_type.kind(), q.dev, q.parent)
            }
            Self::AddQdisc(q) => {
                write!(f, "+ qdisc {} on {} ({:?})", q.qdisc_type.kind(), q.dev, q.parent)
            }
            Self::TcTree { dev, planned, .. } if planned.is_empty() => {
                write!(f, "~ tc {dev} (diffed again after the qdiscs)")
            }
            Self::TcTree { planned, .. } => f.write_str(&planned.join("\n")),
        }
    }
}

/// An apply's steps, in the order it runs them (#518). From
/// [`ConfigDiff::plan`](super::ConfigDiff::plan); run with
/// [`Plan::apply`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "a plan does nothing until applied"]
pub struct Plan {
    /// The steps, in order.
    pub steps: Vec<Step>,
    /// The protocol routes are installed with (#512).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) routes_protocol: Option<RouteProtocol>,
    /// The owner tag a created link gets as its alias (#512).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) owner: Option<String>,
}

impl Plan {
    /// A plan of `steps`, for routes installed with protocol `boot` and
    /// links created without an owner tag.
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps,
            ..Self::default()
        }
    }

    /// Whether it has nothing to do.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// One numbered line per step: what an apply will do, in order.
impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.steps.is_empty() {
            return f.write_str("No changes needed");
        }
        let lines: Vec<String> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| match step.reason() {
                Some(why) => format!("{:>3}. {step}  # {why}", i + 1),
                None => format!("{:>3}. {step}", i + 1),
            })
            .collect();
        f.write_str(&lines.join("\n"))
    }
}

/// A step that changed something, with what undoes it (#518).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JournalEntry {
    /// The step.
    pub step: Step,
    /// Its inverse, when one can be known ([`Step::inverse`]).
    pub inverse: Option<Step>,
}

impl super::ConfigDiff {
    /// The apply as steps, in the order it runs them (#518). See
    /// [`plan`](super::plan).
    pub fn plan(&self) -> Plan {
        let mut steps = Vec::new();
        if self.is_empty() {
            return Plan::default();
        }
        steps.extend(self.links_missing.iter().map(|name| Step::MissingLink {
            name: name.clone(),
        }));
        steps.extend(self.routes_refused.iter().cloned().map(Step::RefuseRoute));
        steps.extend(
            self.links_to_remove
                .iter()
                .filter(|r| r.is_refused())
                .cloned()
                .map(Step::RefuseRemoval),
        );
        for recreate in &self.links_to_recreate {
            steps.push(if recreate.is_refused() {
                Step::RefuseRecreate(recreate.clone())
            } else {
                Step::DeleteForRecreate(recreate.clone())
            });
        }
        steps.extend(
            self.links_to_remove
                .iter()
                .filter(|r| !r.is_refused())
                .cloned()
                .map(Step::RemoveLink),
        );
        steps.extend(self.mtus_first.iter().map(|(link, mtu)| Step::RaiseMtuFirst {
            link: link.clone(),
            mtu: *mtu,
        }));
        steps.extend(self.links_to_add.iter().cloned().map(Step::CreateLink));
        for (name, changes) in &self.links_to_modify {
            steps.push(Step::ModifyLink {
                name: name.clone(),
                changes: changes.clone(),
                mtu_already_set: self.mtus_first.iter().any(|(n, _)| n == name),
            });
        }
        steps.extend(self.bridge_mtus.iter().map(|(bridge, mtu)| Step::PinBridgeMtu {
            bridge: bridge.clone(),
            mtu: *mtu,
        }));
        steps.extend(self.vlans_held_down.iter().map(|vlan| Step::HoldVlanDown {
            vlan: vlan.clone(),
        }));
        // An IPv6 address re-prefixed is deleted at its old prefix right
        // before it is added at the new one: the kernel knows it by the
        // address alone (#461).
        let re_prefixed = |old: &DeclaredAddress, new: &DeclaredAddress| {
            new.address.is_ipv6()
                && old.dev == new.dev
                && old.address == new.address
                && old.prefix_len != new.prefix_len
        };
        for address in &self.addresses_to_add {
            for old in self
                .addresses_to_remove
                .iter()
                .filter(|old| re_prefixed(old, address))
            {
                steps.push(Step::DeleteAddress {
                    address: old.clone(),
                    reason: Some(format!(
                        "re-added at /{}: the kernel knows an address by itself alone",
                        address.prefix_len
                    )),
                });
            }
            steps.push(Step::AddAddress(address.clone()));
        }
        for route in &self.routes_to_add {
            let before = self
                .routes_replaced
                .iter()
                .find(|(r, _)| r == route)
                .map(|(_, before)| before.clone());
            steps.push(Step::ReplaceRoute {
                before,
                after: route.clone(),
            });
        }
        steps.extend(self.qdiscs_to_remove.iter().cloned().map(Step::DeleteQdisc));
        steps.extend(self.qdiscs_to_replace.iter().cloned().map(Step::ReplaceQdisc));
        steps.extend(self.qdiscs_to_add.iter().cloned().map(Step::AddQdisc));
        for (tree, previous) in &self.tc_declared {
            let planned = self
                .tc
                .iter()
                .find(|t| t.dev == tree.dev())
                .map(|t| t.to_string().lines().map(str::to_string).collect())
                .unwrap_or_default();
            steps.push(Step::TcTree {
                dev: tree.dev().to_string(),
                planned,
                tree: Box::new(tree.clone()),
                previous: previous.clone().map(Box::new),
            });
        }
        steps.extend(self.routes_to_remove.iter().cloned().map(Step::DeleteRoute));
        steps.extend(
            self.addresses_to_remove
                .iter()
                .filter(|old| !self.addresses_to_add.iter().any(|new| re_prefixed(old, new)))
                .map(|address| Step::DeleteAddress {
                    address: address.clone(),
                    reason: None,
                }),
        );
        Plan {
            steps,
            routes_protocol: self.routes_protocol,
            owner: self.owner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::{ConfigDiff, DeclaredRouteType, diff::LinkWas};

    fn addr(dev: &str, a: &str, plen: u8) -> DeclaredAddress {
        DeclaredAddress {
            dev: dev.to_string(),
            address: a.parse().unwrap(),
            prefix_len: plen,
        }
    }

    fn route(dst: &str, plen: u8, via: &str) -> DeclaredRoute {
        DeclaredRoute {
            destination: dst.parse().unwrap(),
            prefix_len: plen,
            gateway: Some(via.parse().unwrap()),
            dev: None,
            metric: None,
            table: Some(254),
            route_type: DeclaredRouteType::Unicast,
        }
    }

    /// The steps come in the order the apply runs them, the hidden ones
    /// included, and print that way.
    #[test]
    fn a_plan_lists_every_step_in_apply_order() {
        let mut d = ConfigDiff::default();
        d.routes_to_remove.push(route("10.9.0.0", 16, "10.0.0.9"));
        d.addresses_to_remove.push(addr("d0", "2001:db8::1", 48));
        d.addresses_to_remove.push(addr("d0", "10.0.0.7", 24));
        d.addresses_to_add.push(addr("d0", "2001:db8::1", 64));
        let new = route("10.1.0.0", 16, "10.0.0.2");
        d.routes_replaced.push((new.clone(), route("10.1.0.0", 16, "10.0.0.1")));
        d.routes_to_add.push(new);
        d.mtus_first.push(("d0".into(), 9000));
        d.bridge_mtus.push(("br0".into(), 1500));
        d.links_missing.push("eth9".into());

        let plan = d.plan();
        let kinds: Vec<&str> = plan
            .steps
            .iter()
            .map(|s| match s {
                Step::MissingLink { .. } => "missing",
                Step::RaiseMtuFirst { .. } => "mtu-first",
                Step::PinBridgeMtu { .. } => "pin",
                Step::DeleteAddress { reason: Some(_), .. } => "del-addr-early",
                Step::AddAddress(_) => "add-addr",
                Step::ReplaceRoute { .. } => "route",
                Step::DeleteRoute(_) => "del-route",
                Step::DeleteAddress { .. } => "del-addr",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "missing",
                "mtu-first",
                "pin",
                "del-addr-early",
                "add-addr",
                "route",
                "del-route",
                "del-addr"
            ]
        );
        let shown = plan.to_string();
        assert!(shown.contains("  1. ! link eth9"), "{shown}");
        assert!(
            shown.contains("~ route 10.1.0.0/16 via 10.0.0.2 (replacing 10.1.0.0/16 via 10.0.0.1)"),
            "{shown}"
        );
        assert!(shown.contains("- address 2001:db8::1/48 on d0  # re-added at /64"), "{shown}");
        // The diff says the same of the route: a change, not an addition.
        assert!(d.to_string().contains("~ route 10.1.0.0/16 via 10.0.0.2 (replacing"), "{d}");
        assert!(ConfigDiff::default().plan().is_empty());
    }

    #[test]
    fn inverses_undo_what_can_be_undone() {
        let r = route("10.1.0.0", 16, "10.0.0.2");
        let old = route("10.1.0.0", 16, "10.0.0.1");
        let Some(Step::ReplaceRoute { before, after }) = (Step::ReplaceRoute {
            before: Some(old.clone()),
            after: r.clone(),
        })
        .inverse() else {
            panic!("a replace's inverse is a replace");
        };
        assert_eq!((before, after), (Some(r.clone()), old));
        assert!(matches!(
            Step::ReplaceRoute { before: None, after: r.clone() }.inverse(),
            Some(Step::DeleteRoute(x)) if x == r
        ));
        assert!(matches!(
            Step::AddAddress(addr("d0", "10.0.0.1", 24)).inverse(),
            Some(Step::DeleteAddress { .. })
        ));

        let changes = LinkChanges {
            set_down: true,
            set_mtu: Some(1500),
            unset_master: true,
            was: Some(LinkWas {
                up: true,
                mtu: Some(1400),
                master: Some("br0".into()),
                address: None,
            }),
            ..LinkChanges::default()
        };
        let Some(Step::ModifyLink { changes: back, .. }) = (Step::ModifyLink {
            name: "d0".into(),
            changes,
            mtu_already_set: false,
        })
        .inverse() else {
            panic!("a link change's inverse is a link change");
        };
        assert!(back.set_up && !back.set_down);
        assert_eq!(back.set_mtu, Some(1400));
        assert_eq!(back.set_master.as_deref(), Some("br0"));

        // A kind change, a link this apply creates: nothing to go back to.
        let fresh = LinkChanges {
            set_up: true,
            ..LinkChanges::default()
        };
        assert!(Step::ModifyLink { name: "p0".into(), changes: fresh, mtu_already_set: false }
            .inverse()
            .is_none());
        assert!(Step::MissingLink { name: "x".into() }.inverse().is_none());
    }
}
