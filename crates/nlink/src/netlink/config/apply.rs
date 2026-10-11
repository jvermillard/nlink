//! Configuration application logic.
//!
//! This module applies the computed diff to achieve the desired network state.

use std::net::IpAddr;

use super::{
    diff::{ConfigDiff, PlanOptions, LinkChanges, compute_diff_with_options},
    kind::{KindAttr, KindUpdate, kernel_bond_mode, kernel_macvlan_mode},
    types::{
        DeclaredAddress, DeclaredLink, DeclaredLinkType, DeclaredQdisc, DeclaredRoute,
        NetworkConfig, QdiscParent,
    },
};
pub use crate::netlink::reconcile::ExecOptions;
use super::plan::{Plan, Step};
use crate::netlink::{
    addr::{Ipv4Address, Ipv6Address},
    connection::Connection,
    error::{Error, Result},
    link::{BondLink, BridgeLink, DummyLink, IfbLink, MacvlanLink, VethLink, VlanLink, VxlanLink},
    protocol::Route,
    route::{Ipv4Route, Ipv6Route},
    tc_spec::QdiscSpec,
    types::route::RouteProtocol,
};

/// Options for applying configuration.
///
/// Construct via `Default::default()` + the `with_*` builder
/// methods, NOT via struct-literal syntax:
///
/// ```no_run
/// use nlink::netlink::config::ApplyOptions;
/// let opts = ApplyOptions::default()
///     .with_dry_run(true)
///     .with_continue_on_error(false);
/// ```
///
/// # Default semantics
///
/// `ApplyOptions::default()` produces conservative defaults:
///
/// - `dry_run: false` — operations actually run against the
///   kernel.
/// - `continue_on_error: false` — the first error propagates
///   as `Err`, halting further ops. Partially-applied state
///   is left in the kernel.
///
/// This is the right default; opt in to each surface
/// individually via the builders.
///
/// Plan 188 §2.2 made this `#[non_exhaustive]` so we can grow
/// the option set in future minors without semver breakage —
/// the trade-off is that struct-literal construction is no
/// longer allowed by downstream code. Mirrors `ReconcileOptions`
/// (Plan 163).
///
/// `purge` was removed in 0.19 (Plan 205) because the 0.18 version
/// was a silent no-op, and re-wired in 0.23 with the scope
/// [`PlanOptions::purge`] documents. The removal note outlived the
/// removal by four releases (#335).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ApplyOptions {
    /// What the diff plans: what to remove, what may be recreated, what
    /// the caller owns (#519).
    pub plan: PlanOptions,
    /// How the plan executes: dry run, continue on error, verify (#519).
    pub exec: ExecOptions,
}

impl From<PlanOptions> for ApplyOptions {
    fn from(plan: PlanOptions) -> Self {
        Self {
            plan,
            exec: ExecOptions::default(),
        }
    }
}

impl From<ExecOptions> for ApplyOptions {
    fn from(exec: ExecOptions) -> Self {
        Self {
            plan: PlanOptions::default(),
            exec,
        }
    }
}

/// An apply's execution half: what [`ConfigDiff::apply`] can use of it.
impl From<ApplyOptions> for ExecOptions {
    fn from(options: ApplyOptions) -> Self {
        options.exec
    }
}

impl ApplyOptions {
    /// Toggle dry-run mode. With dry-run on, no kernel
    /// mutations occur — every operation just records what
    /// it WOULD do in `ApplyResult::summary`.
    pub fn with_dry_run(mut self, on: bool) -> Self {
        self.exec.dry_run = on;
        self
    }

    /// Toggle continue-on-error. With this on, the first
    /// per-op failure records into `ApplyResult::errors`
    /// instead of halting `apply`. The remaining operations
    /// still run. Useful for "best-effort" reconciliation
    /// where partial progress is preferable to no progress.
    pub fn with_continue_on_error(mut self, on: bool) -> Self {
        self.exec.continue_on_error = on;
        self
    }

    /// Toggle purge (full-reconcile removals). With purge on, `apply`
    /// computes the diff with [`PlanOptions::purge`] so undeclared
    /// global addresses and `static`/`boot` routes in the tables the
    /// config owns are removed in addition to the additive changes. See
    /// [`PlanOptions::purge`] for the exact safety scope.
    pub fn with_purge(mut self, on: bool) -> Self {
        self.plan.purge = on;
        self
    }

    /// Add route tables to the purge scope. See
    /// [`PlanOptions::purge_tables`].
    pub fn with_purge_tables(mut self, tables: impl IntoIterator<Item = u32>) -> Self {
        self.plan.purge_tables.extend(tables);
        self
    }

    /// Add interfaces to the address purge scope. See
    /// [`PlanOptions::purge_address_devs`].
    pub fn with_purge_address_devs<S: Into<String>>(
        mut self,
        devs: impl IntoIterator<Item = S>,
    ) -> Self {
        self.plan
            .purge_address_devs
            .extend(devs.into_iter().map(Into::into));
        self
    }

    /// Remove what `previous` declared and this config no longer does;
    /// see [`PlanOptions::previous`] (#512).
    pub fn with_previous(
        mut self,
        previous: impl Into<std::sync::Arc<super::NetworkConfig>>,
    ) -> Self {
        self.plan.previous = Some(previous.into());
        self
    }

    /// See [`PlanOptions::recreate_policy`] (#513).
    pub fn with_recreate_policy(mut self, policy: super::RecreatePolicy) -> Self {
        self.plan.recreate_policy = policy;
        self
    }

    /// See [`PlanOptions::caller_owned`] (#513).
    pub fn with_caller_owned(mut self, owned: impl IntoIterator<Item = super::Owned>) -> Self {
        self.plan.owned.extend(owned);
        self
    }

    /// Diff again after the apply and fail if anything is left; see
    /// [`ExecOptions::verify`].
    pub fn with_verify(mut self, on: bool) -> Self {
        self.exec.verify = on;
        self
    }

    /// The plan half, [`Self::plan`].
    #[deprecated(since = "0.32.0", note = "read `ApplyOptions::plan` (#519)")]
    pub fn diff_options(&self) -> PlanOptions {
        self.plan.clone()
    }
}

/// Result of applying configuration.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[must_use = "Inspect `.is_success()`, `.errors`, or `.summary_text()` to learn the outcome"]
#[non_exhaustive]
pub struct ApplyResult {
    /// Number of changes made (or that would be made in dry-run mode).
    pub changes_made: usize,
    /// Errors that occurred during application (when continue_on_error is true).
    pub errors: Vec<ApplyError>,
    /// Summary of what was done.
    pub summary: Vec<String>,
    /// The links the apply deleted and created again (or, on a dry run,
    /// would), each with why and what it lost (#513).
    pub recreated: Vec<super::LinkRecreate>,
    /// What the apply's recreates and removals destroyed that the caller
    /// owns or the recreate policy let go: what to put back (#513).
    pub destroyed: Vec<super::Blocker>,
    /// Each step that changed something, in order, with its inverse where
    /// one can be known (#518). Empty for a dry run.
    pub journal: Vec<super::plan::JournalEntry>,
}

impl ApplyResult {
    /// Check if the application was fully successful.
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// The plan that undoes this apply as far as it can be undone (#518):
    /// the [journal](Self::journal)'s inverses, last step first. A step
    /// with no inverse — a deleted link, a kind change, a replaced qdisc, a
    /// TC tree — is left out; [`irreversible`](Self::irreversible) lists
    /// them. Routes come back with protocol `boot`.
    pub fn undo(&self) -> Plan {
        Plan::new(
            self.journal
                .iter()
                .rev()
                .filter_map(|entry| entry.inverse.clone())
                .collect(),
        )
    }

    /// The steps [`undo`](Self::undo) cannot put back.
    pub fn irreversible(&self) -> impl Iterator<Item = &Step> {
        self.journal
            .iter()
            .filter(|entry| entry.inverse.is_none())
            .map(|entry| &entry.step)
    }

    /// Get a human-readable summary.
    pub fn summary_text(&self) -> String {
        if self.summary.is_empty() {
            "No changes made".to_string()
        } else {
            self.summary.join("\n")
        }
    }
}

/// An error that occurred during configuration application.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug)]
pub struct ApplyError {
    /// What operation was being performed.
    pub operation: String,
    /// The underlying error. Plan 189: serialized as the
    /// `Display` string rather than the structural enum
    /// (the `Error` type is internally varied and not
    /// shape-stable).
    #[cfg_attr(feature = "serde", serde(serialize_with = "serialize_error_as_display"))]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub error: Error,
}

#[cfg(feature = "serde")]
fn serialize_error_as_display<S>(err: &Error, ser: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize as _;
    err.to_string().serialize(ser)
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.error)
    }
}

/// Apply configuration to achieve desired state.
pub async fn apply_config(
    config: &NetworkConfig,
    conn: &Connection<Route>,
    options: ApplyOptions,
) -> Result<ApplyResult> {
    let diff = compute_diff_with_options(config, conn, &options.plan).await?;
    apply_diff(&diff, conn, options.exec).await
}

/// Apply a pre-computed diff.
pub async fn apply_diff(
    diff: &ConfigDiff,
    conn: &Connection<Route>,
    options: ExecOptions,
) -> Result<ApplyResult> {
    let result = apply_steps(diff, conn, options).await?;
    // Diff again, with the config and plan this diff came from (#518).
    if options.verify
        && !options.dry_run
        && let Some(source) = &diff.source
    {
        let (config, plan) = &**source;
        let remaining = compute_diff_with_options(config, conn, plan).await?;
        if !remaining.is_empty() {
            return Err(Error::NotConverged {
                remaining: Box::new(remaining),
            });
        }
    }
    Ok(result)
}

async fn apply_steps(
    diff: &ConfigDiff,
    conn: &Connection<Route>,
    options: ExecOptions,
) -> Result<ApplyResult> {
    // If no changes needed, return early
    if diff.is_empty() {
        return Ok(ApplyResult::default());
    }
    execute_plan(&diff.plan(), conn, options).await
}

impl Plan {
    /// Run the steps, in order (#518). What
    /// [`ConfigDiff::apply`](super::ConfigDiff::apply) runs, and how a plan
    /// from [`ApplyResult::undo`] is applied.
    ///
    /// A refusal step fails the apply, or with
    /// [`ExecOptions::continue_on_error`] is recorded and skipped, as a
    /// failed step is. `verify` is not done here: a plan does not know the
    /// config it came from.
    pub async fn apply(
        &self,
        conn: &Connection<Route>,
        options: impl Into<ExecOptions>,
    ) -> Result<ApplyResult> {
        execute_plan(self, conn, options.into()).await
    }
}

/// What running one step did.
enum Outcome {
    /// It changed the kernel: a summary line, and how many changes.
    Changed(String, usize),
    /// It found the state already right: an optional summary line.
    Unchanged(Option<String>),
}

async fn execute_plan(plan: &Plan, conn: &Connection<Route>, options: ExecOptions) -> Result<ApplyResult> {
    let mut result = ApplyResult::default();
    for step in &plan.steps {
        let outcome = if options.dry_run {
            dry_run_step(step, &mut result)
        } else {
            // Boxed: one future per step kind, nested inline, made the
            // layout of a caller's future overflow rustc's query depth
            // (as #310 and #315 did).
            Box::pin(run_step(step, plan, conn, &mut result)).await
        };
        match outcome {
            Ok(Outcome::Changed(summary, n)) => {
                result.summary.push(summary);
                if !step.is_consequence() {
                    result.changes_made += n;
                }
                if !options.dry_run {
                    result.journal.push(super::plan::JournalEntry {
                        step: step.clone(),
                        inverse: step.inverse(),
                    });
                }
            }
            Ok(Outcome::Unchanged(summary)) => result.summary.extend(summary),
            Err(error) if options.continue_on_error => result.errors.push(ApplyError {
                operation: step_operation(step),
                error,
            }),
            Err(error) => return Err(error),
        }
    }
    Ok(result)
}

/// The step as `ApplyError::operation` names it.
fn step_operation(step: &Step) -> String {
    match step {
        Step::MissingLink { name } => format!("link {name}"),
        Step::RefuseRoute(c) => format!("add route {}/{}", c.route.destination, c.route.prefix_len),
        Step::RefuseRemoval(r) => format!("delete link {}", r.name),
        Step::RefuseRecreate(r) => format!("recreate link {}", r.name),
        Step::DeleteForRecreate(r) => {
            format!("delete link {} to recreate it ({})", r.name, r.reason)
        }
        Step::RemoveLink(r) => format!("delete link {} ({})", r.name, r.link_kind),
        Step::DeleteLink { name } => format!("delete link {name}"),
        Step::RaiseMtuFirst { link, mtu } => format!("set link {link} mtu={mtu}"),
        Step::CreateLink(link) => format!("create link {}", link.name),
        Step::ModifyLink { name, changes, .. } => {
            format!("modify link {} ({})", name, changes.summary())
        }
        Step::PinBridgeMtu { bridge, mtu } => format!("restore bridge {bridge} mtu={mtu}"),
        Step::HoldVlanDown { vlan } => format!("take VLAN {vlan} down"),
        Step::AddAddress(a) => format!("add address {}/{} on {}", a.address, a.prefix_len, a.dev),
        Step::ChangeAddress(a) => {
            format!("change address {}/{} on {}", a.address, a.prefix_len, a.dev)
        }
        Step::DeleteAddress { address: a, .. } => {
            format!("remove address {}/{} on {}", a.address, a.prefix_len, a.dev)
        }
        Step::ReplaceRoute { after, .. } => {
            format!("add route {}/{}", after.destination, after.prefix_len)
        }
        Step::DeleteRoute(r) => format!("remove route {}/{}", r.destination, r.prefix_len),
        Step::SetNeighbour { after, .. } => format!("set {after}"),
        Step::DeleteNeighbour(n) => format!("remove {n}"),
        Step::DeleteQdisc(q) => format!("delete qdisc {} on {}", q.qdisc_type.kind(), q.dev),
        Step::ReplaceQdisc(q) => format!("replace qdisc {} on {}", q.qdisc_type.kind(), q.dev),
        Step::AddQdisc(q) => format!("add qdisc {} on {}", q.qdisc_type.kind(), q.dev),
        Step::TcTree { dev, .. } => format!("tc tree on {dev}"),
    }
}

/// The error a refusal step fails with.
fn refusal(step: &Step) -> Option<Error> {
    Some(match step {
        // A declared link that does not exist and that nothing in this
        // apply creates: a typo, or a device not there yet (#475).
        Step::MissingLink { name } => Error::interface_not_found(name.as_str()),
        // A declared route whose place holds a route the config does not
        // own — the kernel's connected route, an RA, DHCP or routing
        // daemon's — would replace it (#469).
        Step::RefuseRoute(conflict) => Error::NotSupported(format!(
            "route {}/{}: adding it would replace {}, which this config does not own. Give \
             the declared route another metric, or remove the other route, and apply again.",
            conflict.route.destination, conflict.route.prefix_len, conflict.held_by
        )),
        // A removal that would destroy what no config declares (#512).
        Step::RefuseRemoval(removal) => Error::NotSupported(format!(
            "link {}: the previous config declared it and this one does not, but deleting it \
             would destroy what no config declares: {}. Declare them, or remove them, and \
             apply again.",
            removal.name,
            removal
                .blocked_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        // A recreate that would destroy what the config does not declare.
        Step::RefuseRecreate(recreate) => Error::NotSupported(format!(
            "link {}: {} cannot be changed on the live link, and recreating it would \
             destroy what this config does not declare: {}. Declare them, or remove them \
             (or the link), and apply again.",
            recreate.name,
            recreate.reason,
            recreate
                .blocked_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
        _ => return None,
    })
}

/// What a step would do: refusals fail as they would for real, a kernel
/// side effect is not shown, everything else is a "Would …" line.
fn dry_run_step(step: &Step, result: &mut ApplyResult) -> Result<Outcome> {
    if let Some(error) = refusal(step) {
        return Err(error);
    }
    match step {
        Step::DeleteForRecreate(recreate) => {
            result.recreated.push(recreate.clone());
            result.destroyed.extend(recreate.destroys.iter().cloned());
        }
        Step::RemoveLink(removal) => result.destroyed.extend(removal.destroys.iter().cloned()),
        _ => {}
    }
    Ok(match step {
        _ if step.is_consequence() => Outcome::Unchanged(None),
        Step::TcTree { planned, .. } => {
            let lines: Vec<String> = planned.iter().map(|l| format!("Would {l}")).collect();
            if lines.is_empty() {
                Outcome::Unchanged(None)
            } else {
                Outcome::Changed(lines.join("\n"), lines.len())
            }
        }
        _ => Outcome::Changed(format!("Would {}", step_operation(step)), 1),
    })
}

/// The kernel entry a declared neighbour is (#516).
fn neighbour_config(n: &super::DeclaredNeighbour) -> crate::netlink::neigh::Neighbor {
    let c = crate::netlink::neigh::Neighbor::new(n.dev.as_str(), n.destination);
    match n.lladdr {
        _ if n.proxy => c.proxy(),
        Some(mac) => c.permanent().lladdr(mac),
        None => c.permanent(),
    }
}

/// Run one step against the kernel.
async fn run_step(
    step: &Step,
    plan: &Plan,
    conn: &Connection<Route>,
    result: &mut ApplyResult,
) -> Result<Outcome> {
    if let Some(error) = refusal(step) {
        return Err(error);
    }
    Ok(match step {
        Step::MissingLink { .. }
        | Step::RefuseRoute(_)
        | Step::RefuseRemoval(_)
        | Step::RefuseRecreate(_) => unreachable!("a refusal fails above"),
        // A link the kernel deleted along with a recreated one is already
        // gone when its turn comes.
        Step::DeleteForRecreate(recreate) => {
            let deleted = conn.del_link_if_exists(recreate.name.as_str()).await?;
            result.recreated.push(recreate.clone());
            if !deleted {
                return Ok(Outcome::Unchanged(None));
            }
            result.destroyed.extend(recreate.destroys.iter().cloned());
            Outcome::Changed(
                format!(
                    "Deleted link {} to recreate it ({})",
                    recreate.name, recreate.reason
                ),
                1,
            )
        }
        // Before anything is created: a replacement can conflict with it
        // (the same VLAN id on the same parent, the same VNI and port). The
        // links stacked on one are gone with it (#512).
        Step::RemoveLink(removal) => {
            result.destroyed.extend(removal.destroys.iter().cloned());
            if !conn.del_link_if_exists(removal.name.as_str()).await? {
                return Ok(Outcome::Unchanged(None));
            }
            Outcome::Changed(
                format!("Deleted link {} ({})", removal.name, removal.link_kind),
                1,
            )
        }
        Step::DeleteLink { name } => {
            if !conn.del_link_if_exists(name.as_str()).await? {
                return Ok(Outcome::Unchanged(None));
            }
            Outcome::Changed(format!("Deleted link {name}"), 1)
        }
        // `vlan_newlink` / `macvlan_common_newlink` refuse an MTU above
        // the lower device's, so its raise cannot wait for the modify
        // (#473).
        Step::RaiseMtuFirst { link, mtu } => {
            conn.set_link_mtu(link.as_str(), *mtu).await?;
            Outcome::Unchanged(None)
        }
        Step::CreateLink(link) => {
            create_link(conn, link, plan.owner.as_deref()).await?;
            Outcome::Changed(format!("Created link {}", link.name), 1)
        }
        Step::ModifyLink {
            name,
            changes,
            mtu_already_set,
        } => {
            modify_link(conn, name, changes, *mtu_already_set).await?;
            Outcome::Changed(format!("Modified link {} ({})", name, changes.summary()), 1)
        }
        // `br_mtu_auto_adjust()` sets a bridge to its smallest port's MTU
        // when a port joins or leaves, unless the MTU was set through
        // RTM_SETLINK — which this is, so it also sticks from now on.
        Step::PinBridgeMtu { bridge, mtu } => {
            let drifted = conn
                .get_link_by_name(bridge.as_str())
                .await?
                .is_some_and(|l| l.mtu != Some(*mtu));
            if !drifted {
                return Ok(Outcome::Unchanged(None));
            }
            conn.set_link_mtu(bridge.as_str(), *mtu).await?;
            Outcome::Changed(
                format!("Restored bridge {bridge} mtu={mtu} after its ports changed"),
                1,
            )
        }
        // `vlan_device_event()` brings every VLAN on a device up (#436).
        Step::HoldVlanDown { vlan } => {
            let brought_up = conn
                .get_link_by_name(vlan.as_str())
                .await?
                .is_some_and(|l| l.is_up());
            if !brought_up {
                return Ok(Outcome::Unchanged(None));
            }
            conn.set_link_down(vlan.as_str()).await?;
            Outcome::Changed(
                format!("Took VLAN {vlan} down again after its lower device came up"),
                1,
            )
        }
        Step::AddAddress(addr) => match add_address(conn, addr).await {
            Ok(()) => Outcome::Changed(
                format!(
                    "Added address {}/{} on {}",
                    addr.address, addr.prefix_len, addr.dev
                ),
                1,
            ),
            // A re-add the diff scheduled because the link change was
            // expected to flush it, where the kernel kept it after all
            // (`keep_addr_on_down`): the state we wanted, not a change — if
            // what is there is the declared prefix. An IPv6 address at
            // another prefix is EEXIST too, and swallowing that left the
            // wrong prefix in place forever (#461).
            Err(e) if e.is_already_exists() && address_present(conn, addr).await? => {
                Outcome::Unchanged(Some(format!(
                    "Address {}/{} on {} already present",
                    addr.address, addr.prefix_len, addr.dev
                )))
            }
            Err(e) => return Err(e),
        },
        Step::SetNeighbour { after: n, .. } => {
            conn.replace_neighbor(neighbour_config(n)).await?;
            Outcome::Changed(format!("Set {n}"), 1)
        }
        Step::DeleteNeighbour(n) => match conn.del_neighbor(neighbour_config(n)).await {
            Ok(()) => Outcome::Changed(format!("Removed {n}"), 1),
            // Gone before we got to it: a link change flushed it.
            Err(e) if e.is_not_found() => {
                Outcome::Unchanged(Some(format!("{n} already absent")))
            }
            Err(e) => return Err(e),
        },
        Step::ChangeAddress(addr) => {
            change_address(conn, addr).await?;
            Outcome::Changed(
                format!(
                    "Changed address {}/{} on {}",
                    addr.address, addr.prefix_len, addr.dev
                ),
                1,
            )
        }
        Step::DeleteAddress { address: addr, .. } => match del_address(conn, addr).await {
            Ok(()) => Outcome::Changed(
                format!(
                    "Removed address {}/{} on {}",
                    addr.address, addr.prefix_len, addr.dev
                ),
                1,
            ),
            // Gone before we got to it — an IPv6 address the link change
            // flushed, say. The state we wanted, as for a route (#335): not
            // a change we made, and not an error.
            Err(e) if e.is_not_found() || e.errno() == Some(libc::EADDRNOTAVAIL) => {
                Outcome::Unchanged(Some(format!(
                    "Address {}/{} on {} already absent",
                    addr.address, addr.prefix_len, addr.dev
                )))
            }
            Err(e) => return Err(e),
        },
        Step::ReplaceRoute { after: route, .. } => {
            match add_route(
                conn,
                route,
                plan.routes_protocol.unwrap_or(RouteProtocol::Boot),
            )
            .await
            {
                Ok(()) => Outcome::Changed(
                    format!("Added route {}/{}", route.destination, route.prefix_len),
                    1,
                ),
                // A re-add the diff scheduled because a link change was
                // expected to flush the route (#427), where the kernel kept
                // it: the state we wanted, not a change.
                Err(e) if e.is_already_exists() => Outcome::Unchanged(Some(format!(
                    "Route {}/{} already present",
                    route.destination, route.prefix_len
                ))),
                Err(e) => return Err(e),
            }
        }
        Step::DeleteRoute(route) => {
            if del_route(conn, route).await? {
                Outcome::Changed(
                    format!("Removed route {}/{}", route.destination, route.prefix_len),
                    1,
                )
            } else {
                // Gone between diff and apply — the state we wanted (#335).
                Outcome::Unchanged(Some(format!(
                    "Route {}/{} already absent",
                    route.destination, route.prefix_len
                )))
            }
        }
        // The kernel puts its default back (#512).
        Step::DeleteQdisc(qdisc) => {
            let parent = match qdisc.effective_parent() {
                QdiscParent::Root => crate::TcHandle::ROOT,
                QdiscParent::Ingress => crate::TcHandle::INGRESS,
            };
            conn.del_qdisc_if_exists(qdisc.dev.as_str(), parent).await?;
            Outcome::Changed(
                format!("Deleted qdisc {} on {}", qdisc.qdisc_type.kind(), qdisc.dev),
                1,
            )
        }
        Step::ReplaceQdisc(qdisc) => {
            replace_qdisc(conn, qdisc).await?;
            Outcome::Changed(
                format!("Replaced qdisc {} on {}", qdisc.qdisc_type.kind(), qdisc.dev),
                1,
            )
        }
        Step::AddQdisc(qdisc) => {
            add_qdisc(conn, qdisc).await?;
            Outcome::Changed(
                format!("Added qdisc {} on {}", qdisc.qdisc_type.kind(), qdisc.dev),
                1,
            )
        }
        // Diffed again against the device as the steps above left it: a
        // root qdisc replaced or a link recreated took its tree, and a
        // redirect's target may have a new ifindex (#514).
        Step::TcTree {
            dev,
            tree,
            previous,
            ..
        } => match super::tc_tree::apply_declared(conn, tree, previous.as_deref()).await? {
            0 => Outcome::Unchanged(None),
            n => Outcome::Changed(format!("Applied TC tree on {dev} ({n} changes)"), n),
        },
    })
}

// ============================================================================
// Helper functions for applying individual changes
// ============================================================================

/// Refuse a declared MAC on a link kind that has no hardware address.
///
/// ovpn and netkit in L3 mode (netkit's default) are `ARPHRD_NONE`
/// devices: the kernel refuses `IFLA_ADDRESS` on them (netkit answers a
/// bare EOPNOTSUPP), and if the address were dropped instead the diff
/// would ask for it on every apply. Say which knob is wrong instead.
/// The typed config `create_link` sends for a declared link; `None` for a
/// physical device, which cannot be created. `diff_against` encodes the
/// same configs to predict recreates without a kernel (#513).
pub(crate) fn link_config(
    link: &DeclaredLink,
) -> Option<Box<dyn crate::netlink::link::LinkConfig>> {
    let config: Box<dyn crate::netlink::link::LinkConfig> = match &link.link_type {
        DeclaredLinkType::Dummy => {
            let mut config = DummyLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Veth { peer } => {
            let mut config = VethLink::new(&link.name, peer);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Bridge => {
            let mut config = BridgeLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            // The declared options, at create (#516).
            if let Some(b) = &link.bridge {
                let ms = |t: std::time::Duration| u32::try_from(t.as_millis()).unwrap_or(u32::MAX);
                if let Some(on) = b.vlan_filtering {
                    config = config.vlan_filtering(on);
                }
                if let Some(vid) = b.vlan_default_pvid {
                    config = config.vlan_default_pvid(vid);
                }
                if let Some(on) = b.stp {
                    config = config.stp(on);
                }
                if let Some(p) = b.priority {
                    config = config.priority(p);
                }
                if let Some(t) = b.ageing_time {
                    config = config.ageing_time_ms(ms(t));
                }
                if let Some(t) = b.forward_delay {
                    config = config.forward_delay_ms(ms(t));
                }
                if let Some(t) = b.hello_time {
                    config = config.hello_time_ms(ms(t));
                }
                if let Some(t) = b.max_age {
                    config = config.max_age_ms(ms(t));
                }
            }
            Box::new(config)
        }
        DeclaredLinkType::Vlan {
            parent,
            vlan_id,
            protocol,
        } => {
            let mut config = VlanLink::new(&link.name, parent, *vlan_id);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(p) = protocol {
                config = config.protocol(*p);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Vxlan {
            vni,
            remote,
            local,
            port,
            underlay_dev,
        } => {
            let mut config = VxlanLink::new(&link.name, *vni);
            // Both families: IPv6 endpoints used to be dropped here,
            // silently, because the builder had no way to write them
            // (#418).
            match remote {
                Some(IpAddr::V4(a)) => config = config.remote(*a),
                Some(IpAddr::V6(a)) => config = config.remote6(*a),
                None => {}
            }
            match local {
                Some(IpAddr::V4(a)) => config = config.local(*a),
                Some(IpAddr::V6(a)) => config = config.local6(*a),
                None => {}
            }
            if let Some(p) = port {
                config = config.port(*p);
            }
            if let Some(dev) = underlay_dev {
                config = config.dev(dev);
            }
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Ipvlan {
            parent,
            mode,
            isolation,
        } => {
            use crate::netlink::link::{IpvlanFlags, IpvlanLink, IpvlanMode as K};
            let mut config = IpvlanLink::new(&link.name, parent)
                .mode(match mode {
                    super::types::IpvlanMode::L2 => K::L2,
                    super::types::IpvlanMode::L3 => K::L3,
                    super::types::IpvlanMode::L3s => K::L3S,
                })
                .flags(match isolation {
                    super::types::IpvlanIsolation::Bridge => IpvlanFlags::Bridge,
                    super::types::IpvlanIsolation::Private => IpvlanFlags::Private,
                    super::types::IpvlanIsolation::Vepa => IpvlanFlags::Vepa,
                });
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            Box::new(config)
        }
        DeclaredLinkType::Gre(p) => {
            let mut c = crate::netlink::link::GreLink::new(&link.name);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.ttl {
                c = c.ttl(v);
            }
            if let Some(v) = p.key {
                c = c.key(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Gretap(p) => {
            let mut c = crate::netlink::link::GretapLink::new(&link.name);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.ttl {
                c = c.ttl(v);
            }
            if let Some(v) = p.key {
                c = c.key(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Ipip(p) => {
            let mut c = crate::netlink::link::IpipLink::new(&link.name);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.ttl {
                c = c.ttl(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Sit(p) => {
            let mut c = crate::netlink::link::SitLink::new(&link.name);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.ttl {
                c = c.ttl(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Vti(p) => {
            let mut c = crate::netlink::link::VtiLink::new(&link.name);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.key {
                c = c.ikey(v).okey(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            Box::new(c)
        }
        DeclaredLinkType::Ip6tnl(p) => {
            let mut c = crate::netlink::link::Ip6tnlLink::new(&link.name).mode(p.mode);
            if let Some(v) = p.local {
                c = c.local(v);
            }
            if let Some(v) = p.remote {
                c = c.remote(v);
            }
            if let Some(v) = p.hoplimit {
                c = c.hoplimit(v);
            }
            if let Some(v) = p.encap_limit {
                c = c.encap_limit(v);
            }
            if let Some(v) = &p.underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Xfrm { if_id, underlay_dev } => {
            let mut c = crate::netlink::link::XfrmLink::new(&link.name, *if_id);
            if let Some(v) = underlay_dev {
                c = c.link(v.as_str());
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Geneve {
            vni,
            remote,
            ttl,
            tos,
            port,
        } => {
            let mut c = crate::netlink::link::GeneveLink::new(&link.name, *vni);
            match remote {
                Some(IpAddr::V4(a)) => c = c.remote(*a),
                Some(IpAddr::V6(a)) => c = c.remote6(*a),
                None => {}
            }
            if let Some(v) = ttl {
                c = c.ttl(*v);
            }
            if let Some(v) = tos {
                c = c.tos(*v);
            }
            if let Some(v) = port {
                c = c.port(*v);
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            if let Some(addr) = link.address {
                c = c.address(addr);
            }
            Box::new(c)
        }
        DeclaredLinkType::Macsec {
            parent,
            sci,
            port,
            encrypt,
            protect,
            include_sci,
            replay_window,
        } => {
            let mut c = crate::netlink::link::MacsecLink::new(&link.name, parent);
            if let Some(v) = sci {
                c = c.sci(*v);
            }
            if let Some(v) = port {
                c = c.port(*v);
            }
            if let Some(v) = encrypt {
                c = c.encrypt(*v);
            }
            if let Some(v) = protect {
                c = c.protect(*v);
            }
            if let Some(v) = include_sci {
                c = c.include_sci(*v);
            }
            if let Some(w) = replay_window {
                c = c.replay_protect(true).replay_window(*w);
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Bareudp {
            port,
            ethertype,
            srcport_min,
            multiproto,
        } => {
            let mut c = crate::netlink::link::BareudpLink::new(&link.name, *port, *ethertype);
            if *multiproto {
                c = c.multiproto_mode();
            }
            if let Some(v) = srcport_min {
                c = c.srcport_min(*v);
            }
            if let Some(mtu) = link.mtu {
                c = c.mtu(mtu);
            }
            Box::new(c)
        }
        DeclaredLinkType::Macvtap { parent, mode } => {
            let mut config = crate::netlink::link::MacvtapLink::new(&link.name, parent)
                .mode(kernel_macvlan_mode(*mode));
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Macvlan { parent, mode } => {
            let mut config = MacvlanLink::new(&link.name, parent);
            config = config.mode(kernel_macvlan_mode(*mode));
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Bond {
            mode,
            miimon,
            xmit_hash_policy,
            min_links,
            ad_select,
            lacp_rate,
            downdelay,
            updelay,
            resend_igmp,
        } => {
            let mut config = BondLink::new(&link.name).mode(kernel_bond_mode(*mode));
            if let Some(ms) = miimon {
                config = config.miimon(*ms);
            }
            if let Some(policy) = xmit_hash_policy {
                config = config.xmit_hash_policy(*policy);
            }
            if let Some(count) = min_links {
                config = config.min_links(*count);
            }
            if let Some(sel) = ad_select {
                config = config.ad_select(*sel);
            }
            if let Some(rate) = lacp_rate {
                config = config.lacp_rate(*rate);
            }
            if let Some(ms) = downdelay {
                config = config.downdelay(*ms);
            }
            if let Some(ms) = updelay {
                config = config.updelay(*ms);
            }
            if let Some(count) = resend_igmp {
                config = config.resend_igmp(*count);
            }
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Ifb => {
            let mut config = IfbLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Vrf { table } => {
            let mut config = crate::netlink::link::VrfLink::new(&link.name, *table);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        DeclaredLinkType::Ovpn => {
            let mut config = crate::netlink::link::OvpnLink::new(&link.name);
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            Box::new(config)
        }
        DeclaredLinkType::Netkit {
            peer,
            mode,
            primary_policy,
            peer_policy,
            scrub,
            peer_scrub,
        } => {
            let mut config = crate::netlink::link::NetkitLink::new(&link.name, peer);
            if let Some(m) = mode {
                config = config.mode(*m);
            }
            if let Some(p) = primary_policy {
                config = config.policy(*p);
            }
            if let Some(p) = peer_policy {
                config = config.peer_policy(*p);
            }
            if let Some(s) = scrub {
                config = config.scrub(*s);
            }
            if let Some(s) = peer_scrub {
                config = config.peer_scrub(*s);
            }
            if let Some(mtu) = link.mtu {
                config = config.mtu(mtu);
            }
            if let Some(addr) = link.address {
                config = config.address(addr);
            }
            Box::new(config)
        }
        // Physical interfaces can't be created, only configured.
        DeclaredLinkType::Physical => return None,
    };
    Some(config)
}

async fn create_link(
    conn: &Connection<Route>,
    link: &DeclaredLink,
    owner: Option<&str>,
) -> Result<()> {
    if let Some(config) = link_config(link) {
        conn.add_link(config).await?;
        // The owner tag: the kernel ignores IFLA_IFALIAS on create, so it
        // is set right after (#512, #517).
        if let Some(owner) = owner {
            conn.set_link_alias(link.name.as_str(), owner).await?;
        }
        // The declared attributes beyond the create's (#516), before the
        // link comes up.
        if !link.attrs.is_empty() {
            let changes = super::diff::LinkChanges::declaring(&link.attrs);
            set_link_attrs(conn, &link.name, &changes).await?;
        }
    }

    // Enslave before bringing up: a bond refuses a port that is already
    // up (see `enslave`).
    if let Some(master) = link.master.name() {
        enslave(conn, &link.name, master).await?;
    }
    // A port's options and VLANs, once it is one (#516).
    if let Some(port) = &link.port {
        let config = port.to_config();
        if !config.is_empty() {
            conn.set_bridge_port(link.name.as_str(), config).await?;
        }
        if let Some(vlans) = &port.vlans {
            set_port_vlans(conn, &link.name, vlans).await?;
        }
    }

    match link.state {
        super::types::LinkState::Up => conn.set_link_up(&link.name).await?,
        // Created down, but a bond opens the port it enslaves.
        super::types::LinkState::Down if link.master.name().is_some() => {
            conn.set_link_down(&link.name).await?;
        }
        _ => {}
    }

    Ok(())
}

/// One link's changes, in the order the kernel needs them (#473). `mtu_done`
/// skips an MTU step 1a already set.
async fn modify_link(
    conn: &Connection<Route>,
    name: &str,
    changes: &LinkChanges,
    mtu_done: bool,
) -> Result<()> {
    if let Some(update) = &changes.kind_update {
        change_kind_params(conn, name, update).await?;
    }
    // A device without IFF_LIVE_ADDR_CHANGE — most hardware — answers EBUSY
    // to a MAC change while it is up (`eth_prepare_mac_addr_change`), so the
    // MAC goes in while it is down: after it goes down, before it comes up.
    // It used to follow both.
    if changes.set_down {
        conn.set_link_down(name).await?;
    }
    if let Some(address) = changes.set_address {
        conn.set_link_address(name, address).await?;
    }
    // Master changes before the state: enslaving to a bond needs the port
    // down, and a bond opens the port it enslaves and closes the one it
    // releases, so the declared up/down state is only settled after them.
    let master_changes = changes.set_master.is_some() || changes.unset_master;
    if let Some(master) = &changes.set_master {
        enslave(conn, name, master).await?;
    }
    if changes.unset_master {
        conn.set_link_nomaster(name).await?;
    }
    // A port's options and VLANs, after it joined its bridge (#516).
    if let Some(port) = &changes.port_update {
        conn.set_bridge_port(name, port.clone()).await?;
    }
    if let Some(vlans) = &changes.port_vlans {
        set_port_vlans(conn, name, vlans).await?;
    }
    // After the master: a bond gives the port it enslaves its own MTU, and a
    // declared one wins.
    if let Some(mtu) = changes.set_mtu
        && !mtu_done
    {
        conn.set_link_mtu(name, mtu).await?;
    }
    set_link_attrs(conn, name, changes).await?;
    if changes.set_up {
        conn.set_link_up(name).await?;
    }
    if changes.set_down && master_changes {
        conn.set_link_down(name).await?;
    }
    Ok(())
}

/// Make a bridge port's VLANs exactly `want` (#516), against a fresh read:
/// a port gets the bridge's default PVID when it joins, which no diff made
/// before the join can know of. Adds go first, which also moves the PVID,
/// then what is not declared goes.
async fn set_port_vlans(
    conn: &Connection<Route>,
    name: &str,
    want: &[super::types::PortVlan],
) -> Result<()> {
    use crate::netlink::bridge_vlan::BridgeVlanBuilder;
    let ifindex = conn
        .get_link_by_name(name)
        .await?
        .ok_or_else(|| Error::interface_not_found(name))?
        .ifindex();
    let have = conn.get_bridge_vlans_by_index(ifindex).await?;
    for v in want {
        let same = have
            .iter()
            .any(|h| h.vid() == v.vid && h.is_pvid() == v.pvid && h.is_untagged() == v.untagged);
        if same {
            continue;
        }
        let mut b = BridgeVlanBuilder::new(v.vid).ifindex(ifindex);
        if v.pvid {
            b = b.pvid();
        }
        if v.untagged {
            b = b.untagged();
        }
        conn.add_bridge_vlan(b).await?;
    }
    for h in &have {
        if !want.iter().any(|w| w.vid == h.vid()) {
            conn.del_bridge_vlan_by_index(ifindex, h.vid()).await?;
        }
    }
    Ok(())
}

/// Set what `changes` says of the attributes beyond kind, state, MTU,
/// master and MAC (#516), each its own request.
async fn set_link_attrs(conn: &Connection<Route>, name: &str, changes: &LinkChanges) -> Result<()> {
    let has_any = changes.set_txqlen.is_some()
        || changes.set_alias.is_some()
        || changes.set_group.is_some()
        || changes.set_gso_max_size.is_some()
        || changes.set_gso_max_segs.is_some()
        || changes.set_gro_max_size.is_some()
        || changes.set_promisc.is_some()
        || changes.set_protodown.is_some()
        || !changes.add_altnames.is_empty()
        || !changes.del_altnames.is_empty()
        || !changes.set_ipv4_conf.is_empty()
        || !changes.set_ipv6_conf.is_empty()
        || changes.set_addr_gen_mode.is_some()
        || changes.set_ipv6_token.is_some();
    if !has_any {
        return Ok(());
    }
    let ifindex = conn
        .get_link_by_name(name)
        .await?
        .ok_or_else(|| Error::interface_not_found(name))?
        .ifindex();
    if let Some(v) = changes.set_txqlen {
        conn.set_link_txqlen_by_index(ifindex, v).await?;
    }
    if let Some(alias) = &changes.set_alias {
        conn.set_link_alias_by_index(ifindex, alias).await?;
    }
    if let Some(v) = changes.set_group {
        conn.set_link_group_by_index(ifindex, v).await?;
    }
    if let Some(v) = changes.set_gso_max_size {
        conn.set_link_gso_max_size_by_index(ifindex, v).await?;
    }
    if let Some(v) = changes.set_gso_max_segs {
        conn.set_link_gso_max_segs_by_index(ifindex, v).await?;
    }
    if let Some(v) = changes.set_gro_max_size {
        conn.set_link_gro_max_size_by_index(ifindex, v).await?;
    }
    if let Some(on) = changes.set_promisc {
        conn.set_link_promisc_by_index(ifindex, on).await?;
    }
    if let Some(on) = changes.set_protodown {
        conn.set_link_protodown_by_index(ifindex, on).await?;
    }
    for altname in &changes.del_altnames {
        conn.del_link_altname_by_index(ifindex, altname).await?;
    }
    for altname in &changes.add_altnames {
        conn.add_link_altname_by_index(ifindex, altname).await?;
    }
    if !changes.set_ipv4_conf.is_empty() {
        conn.set_ipv4_devconf_by_index(ifindex, &changes.set_ipv4_conf)
            .await?;
    }
    if !changes.set_ipv6_conf.is_empty() {
        set_ipv6_devconf(conn, name, &changes.set_ipv6_conf)?;
    }
    if let Some(mode) = changes.set_addr_gen_mode {
        conn.set_addr_gen_mode_by_index(ifindex, mode).await?;
    }
    if let Some(token) = changes.set_ipv6_token {
        conn.set_ipv6_token_by_index(ifindex, token).await?;
    }
    Ok(())
}

/// Write IPv6 per-device settings to `/proc/sys/net/ipv6/conf/<dev>/` in
/// the connection's namespace, from a thread that enters it (#516): the
/// kernel takes them no other way.
fn set_ipv6_devconf(
    conn: &Connection<Route>,
    dev: &str,
    settings: &[(crate::netlink::devconf::Ipv6Devconf, i32)],
) -> Result<()> {
    conn.netns()?.run(|| -> Result<()> {
        for (d, v) in settings {
            crate::netlink::sysctl::set(
                &crate::netlink::sysctl::ipv6_conf_key(dev, d.name()),
                &v.to_string(),
            )?;
        }
        Ok(())
    })?
}

/// Change a live link's kind parameters in place: only the attributes
/// that differ, in one `RTM_NEWLINK` its kind's `changelink` takes.
async fn change_kind_params(
    conn: &Connection<Route>,
    name: &str,
    update: &KindUpdate,
) -> Result<()> {
    let ifindex = conn
        .get_link_by_name(name)
        .await?
        .ok_or_else(|| Error::interface_not_found(name))?
        .ifindex();
    // Links named by an attribute (a VXLAN underlay) resolve now: they
    // may have been created by this apply.
    let mut ifindexes = Vec::new();
    for attr in &update.attrs {
        if let KindAttr::Ifindex(t, dev) = attr {
            let link = conn
                .get_link_by_name(dev)
                .await?
                .ok_or_else(|| Error::interface_not_found(dev))?;
            ifindexes.push((*t, link.ifindex()));
        }
    }
    conn.change_link_info_data(ifindex, update.kind, |b| {
        for attr in &update.attrs {
            match attr {
                KindAttr::U8(t, v) => b.append_attr_u8(*t, *v),
                KindAttr::U16(t, v) => b.append_attr_u16(*t, *v),
                KindAttr::U32(t, v) => b.append_attr_u32(*t, *v),
                KindAttr::Bytes(t, v) => b.append_attr(*t, v),
                KindAttr::Ifindex(..) => {}
            }
        }
        for (t, idx) in ifindexes {
            b.append_attr_u32(t, idx);
        }
    })
    .await
}

/// Make `master` the master of `name`.
///
/// A bond refuses a port that is up — `bond_enslave()` (drivers/net/
/// bonding/bond_main.c) answers EPERM, "Device can not be enslaved while
/// up" — and opens the port itself once it is enslaved. `create_link`
/// used to bring a link up before enslaving it, so every bond port
/// declared `.up()` failed the apply, and so did moving an up link into
/// a bond. For a bond master the port goes down first, as ifenslave and
/// systemd-networkd do; other masters take an up port as it is.
async fn enslave(conn: &Connection<Route>, name: &str, master: &str) -> Result<()> {
    let master_is_bond = conn
        .get_link_by_name(master)
        .await?
        .is_some_and(|m| m.kind() == Some("bond"));
    if master_is_bond
        && conn
            .get_link_by_name(name)
            .await?
            .is_some_and(|port| port.is_up())
    {
        conn.set_link_down(name).await?;
    }
    conn.set_link_master(name, master).await
}

async fn add_address(conn: &Connection<Route>, addr: &DeclaredAddress) -> Result<()> {
    match address_config(addr) {
        AddressConfigOf::V4(c) => conn.add_address(c).await,
        AddressConfigOf::V6(c) => conn.add_address(c).await,
    }
}

/// Change an address's metric, lifetimes or (IPv6) flags in place, with
/// `NLM_F_REPLACE` and everything declared (#516).
async fn change_address(conn: &Connection<Route>, addr: &DeclaredAddress) -> Result<()> {
    match address_config(addr) {
        AddressConfigOf::V4(c) => conn.replace_address(c).await,
        AddressConfigOf::V6(c) => conn.replace_address(c).await,
    }
}

enum AddressConfigOf {
    V4(Ipv4Address),
    V6(Ipv6Address),
}

/// The imperative config for a declared address, with every attribute it
/// declares (#516).
fn address_config(addr: &DeclaredAddress) -> AddressConfigOf {
    let t = &addr.attrs;
    let lifetimes = t.lifetimes.map(|(valid, preferred)| {
        let secs = |d: std::time::Duration| u32::try_from(d.as_secs()).unwrap_or(u32::MAX - 1);
        (secs(valid), secs(preferred))
    });
    match addr.address {
        IpAddr::V4(v4) => {
            let mut c = Ipv4Address::new(&addr.dev, v4, addr.prefix_len);
            if let Some(IpAddr::V4(peer)) = t.peer {
                c = c.peer(peer);
            }
            if let Some(label) = &t.label {
                c = c.label(label.clone());
            }
            if let Some(metric) = t.metric {
                c = c.metric(metric);
            }
            if t.noprefixroute {
                c = c.noprefixroute();
            }
            if t.home {
                c = c.home();
            }
            if let Some((valid, preferred)) = lifetimes {
                c = c.valid_lifetime(valid).preferred_lifetime(preferred);
            }
            AddressConfigOf::V4(c)
        }
        IpAddr::V6(v6) => {
            let mut c = Ipv6Address::new(&addr.dev, v6, addr.prefix_len);
            if let Some(IpAddr::V6(peer)) = t.peer {
                c = c.peer(peer);
            }
            if let Some(metric) = t.metric {
                c = c.metric(metric);
            }
            for (on, set) in [
                (t.nodad, Ipv6Address::nodad as fn(Ipv6Address) -> Ipv6Address),
                (t.optimistic, Ipv6Address::optimistic),
                (t.noprefixroute, Ipv6Address::noprefixroute),
                (t.home, Ipv6Address::home),
                (t.mngtmpaddr, Ipv6Address::mngtmpaddr),
            ] {
                if on {
                    c = set(c);
                }
            }
            if let Some((valid, preferred)) = lifetimes {
                c = c.valid_lifetime(valid).preferred_lifetime(preferred);
            }
            AddressConfigOf::V6(c)
        }
    }
}

async fn add_route(
    conn: &Connection<Route>,
    route: &DeclaredRoute,
    protocol: RouteProtocol,
) -> Result<()> {
    match route.destination {
        IpAddr::V4(dst) => {
            let mut config = Ipv4Route::from_addr(dst, route.prefix_len).protocol(protocol);

            // Set gateway
            if let Some(IpAddr::V4(gw)) = route.gateway {
                config = config.gateway(gw);
            }

            // Set device
            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }

            // Set metric
            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }

            // Set table
            if let Some(table) = route.table {
                config = config.table(table);
            }

            // Set route type — the same mapping the diff compares with.
            config = config.route_type(route.route_type.kernel_type());
            if let Some(IpAddr::V4(src)) = route.attrs.prefsrc {
                config = config.prefsrc(src);
            }
            if let Some(scope) = route.attrs.scope {
                config = config.scope(scope);
            }
            if route.attrs.onlink {
                config = config.onlink();
            }
            if let Some(metrics) = route.attrs.metrics() {
                config = config.metrics(metrics);
            }

            // Plan 207d H3 — use NLM_F_REPLACE so a change to
            // gateway/dev/metric on the same `(dst, prefix, table)`
            // atomically swaps the existing route instead of
            // failing with EEXIST (and silently no-op'ing because
            // the pre-0.19 diff didn't notice the gateway change
            // at all). New routes are also accepted by replace.
            conn.replace_route(config).await
        }
        IpAddr::V6(dst) => {
            let mut config = Ipv6Route::from_addr(dst, route.prefix_len).protocol(protocol);

            if let Some(IpAddr::V6(gw)) = route.gateway {
                config = config.gateway(gw);
            }

            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }

            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }

            if let Some(table) = route.table {
                config = config.table(table);
            }

            config = config.route_type(route.route_type.kernel_type());
            if let Some(IpAddr::V6(src)) = route.attrs.prefsrc {
                config = config.prefsrc(src);
            }
            if let Some(scope) = route.attrs.scope {
                config = config.scope(scope);
            }
            if route.attrs.onlink {
                config = config.onlink();
            }
            if let Some(metrics) = route.attrs.metrics() {
                config = config.metrics(metrics);
            }

            // Plan 207d H3 — use NLM_F_REPLACE so a change to
            // gateway/dev/metric on the same `(dst, prefix, table)`
            // atomically swaps the existing route instead of
            // failing with EEXIST (and silently no-op'ing because
            // the pre-0.19 diff didn't notice the gateway change
            // at all). New routes are also accepted by replace.
            conn.replace_route(config).await
        }
    }
}

async fn del_address(conn: &Connection<Route>, addr: &DeclaredAddress) -> Result<()> {
    // The peer names a point-to-point address (#516).
    match address_config(addr) {
        AddressConfigOf::V4(c) => conn.del_address_config(c).await,
        AddressConfigOf::V6(c) => conn.del_address_config(c).await,
    }
}

/// `Ok(true)` when the route was deleted, `Ok(false)` when the kernel
/// no longer had it.
/// Does `addr`'s device hold `addr` at the declared prefix?
async fn address_present(conn: &Connection<Route>, addr: &DeclaredAddress) -> Result<bool> {
    let Some(link) = conn.get_link_by_name(&addr.dev).await? else {
        return Ok(false);
    };
    Ok(conn
        .get_addresses_by_index(link.ifindex())
        .await?
        .iter()
        .any(|a| a.address == Some(addr.address) && a.prefix_len() == addr.prefix_len))
}

async fn del_route(conn: &Connection<Route>, route: &DeclaredRoute) -> Result<bool> {
    // Delete the way `ip route del` does: type 0, scope
    // `RT_SCOPE_NOWHERE`, protocol 0, and only the attributes that pick
    // *this* route out — metric, device, gateway, table. The kernel
    // matches type, scope and protocol whenever they are set, and the
    // builder's defaults (unicast, boot) are what it sent before, so a
    // `proto static` route or a blackhole/unreachable/prohibit route was
    // never matched: the delete came back ESRCH, counted as "already
    // absent", and the next diff listed the route again, forever (#467).
    use crate::netlink::types::route::{RouteProtocol, RouteScope, RouteType};
    match route.destination {
        IpAddr::V4(dst) => {
            let mut config = Ipv4Route::from_addr(dst, route.prefix_len)
                .route_type(RouteType::Unspec)
                .protocol(RouteProtocol::Unspec)
                .scope(RouteScope::Nowhere);
            if let Some(IpAddr::V4(gw)) = route.gateway {
                config = config.gateway(gw);
            }
            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }
            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }
            if let Some(table) = route.table {
                config = config.table(table);
            }
            conn.del_route_if_exists(config).await
        }
        IpAddr::V6(dst) => {
            let mut config = Ipv6Route::from_addr(dst, route.prefix_len)
                .route_type(RouteType::Unspec)
                .protocol(RouteProtocol::Unspec)
                .scope(RouteScope::Nowhere);
            if let Some(IpAddr::V6(gw)) = route.gateway {
                config = config.gateway(gw);
            }
            if let Some(dev) = &route.dev {
                config = config.dev(dev);
            }
            if let Some(metric) = route.metric {
                config = config.metric(metric);
            }
            if let Some(table) = route.table {
                config = config.table(table);
            }
            conn.del_route_if_exists(config).await
        }
    }
}

async fn add_qdisc(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    // At its declared handle, or `1:` for a classful kind, so its classes
    // and filters can name it (#514). The spec is the config itself (#515).
    let handle = qdisc.effective_handle();
    let root = crate::TcHandle::ROOT;
    let dev = qdisc.dev.as_str();
    match &qdisc.qdisc_type {
        spec @ (QdiscSpec::Ingress | QdiscSpec::Clsact) => conn.add_qdisc(dev, spec).await,
        // The diff puts it in `qdiscs_to_remove`, never here; deleting the
        // root is what it asks for all the same.
        QdiscSpec::KernelDefault => conn.del_qdisc_if_exists(dev, root).await.map(drop),
        spec => conn.add_qdisc_full(dev, root, handle, spec).await,
    }
}

async fn replace_qdisc(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    // Plan 207f M18 — use atomic `RTM_NEWQDISC` with `NLM_F_REPLACE`
    // (`Connection::replace_qdisc*`) instead of the pre-0.19
    // del-then-add sequence. The old sequence had a transient
    // window between `del_qdisc` (which restored the default
    // `pfifo_fast`/`mq`) and `add_qdisc` (which installed the
    // new declared kind). If `add_qdisc` failed mid-window the
    // interface kept the kernel-default qdisc, NOT the previous
    // declared one — visible state divergence on apply failure.
    //
    // The atomic form is unsupported on a small set of qdiscs
    // (`Ingress`, `Clsact`) where the kernel rejects REPLACE
    // semantically; for those we fall back to del+add since the
    // kind is parent-fixed (ingress / clsact slots).
    //
    // A same-kind replace of a kind with no change operation (`sfq`) is
    // `Connection::replace_qdisc`'s to handle now: it grafts a new qdisc
    // over the live one instead of answering EINVAL (#361, #486).
    match &qdisc.qdisc_type {
        QdiscSpec::Ingress | QdiscSpec::Clsact => {
            // Kernel does not accept NLM_F_REPLACE on these
            // pseudo-qdiscs (the kind IS the slot). Use del+add.
            // `effective_parent`, not `parent`: a clsact/ingress
            // declaration left at the `Root` default used to delete the
            // interface's root qdisc here — and then fail to install
            // the hook, leaving the interface bare. The hook kinds have
            // exactly one legal slot.
            let parent_handle = match qdisc.effective_parent() {
                QdiscParent::Root => crate::TcHandle::ROOT,
                QdiscParent::Ingress => crate::TcHandle::INGRESS,
            };
            match conn.del_qdisc(&qdisc.dev, parent_handle).await {
                Ok(()) => {}
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
            return add_qdisc(conn, qdisc).await;
        }
        QdiscSpec::Htb(cfg) => {
            refuse_htb_change_in_place(conn, &qdisc.dev, cfg).await?;
        }
        _ => {}
    }

    // `replace_qdisc` is kind-aware (#486): it recreates a kind with no
    // change operation (sfq) instead of answering EINVAL, which used to
    // need a del+add fallback here.
    atomic_replace(conn, qdisc).await
}

/// Refuse a declared HTB root that would replace a live HTB root in place.
///
/// The diff only asks for that when the declared HTB differs from the
/// live one — in practice its `default_class`. But `sch_htb` has no
/// `Qdisc_ops.change`, so a same-kind replace is `qdisc_change()` →
/// EINVAL, "Change operation not supported by specified qdisc". The only
/// way to a different `default` is delete + add, and deleting an HTB root
/// deletes every class, leaf and filter under it — a whole shaping tree
/// this config does not describe, since `NetworkConfig` declares only the
/// root qdisc. That is not a side effect to take implicitly, unlike sfq
/// (whose del+add fallback loses nothing but the qdisc itself). So say
/// what cannot change and what to do, rather than surface the kernel's
/// bare EINVAL on every apply.
///
/// A live root of another kind is fine: replacing it creates the HTB and
/// grafts it, no change op involved.
async fn refuse_htb_change_in_place(
    conn: &Connection<Route>,
    dev: &str,
    declared: &crate::netlink::tc::HtbQdiscConfig,
) -> Result<()> {
    use crate::netlink::tc_options::QdiscOptions;

    let live = conn.get_qdiscs_by_name(dev).await?;
    let Some(root) = live.iter().find(|q| q.is_root() && q.kind() == Some("htb")) else {
        return Ok(());
    };
    let live_params = match root.options() {
        Some(QdiscOptions::Htb(opts)) => {
            format!("default_class {:#x}, r2q {}", opts.default_class, opts.rate2quantum)
        }
        _ => "unreadable options".to_string(),
    };
    Err(Error::NotSupported(format!(
        "htb on {dev}: the live HTB root ({live_params}) cannot be changed in place to the \
         declared one (default_class {:#x}, r2q {}). The kernel's htb has no change \
         operation, so the only way is to delete the root qdisc, which deletes every class \
         and filter under it; nlink will not do that implicitly. Delete it \
         (Connection::del_qdisc) and apply again.",
        declared.default_class, declared.r2q
    )))
}

/// Atomic replace via NLM_F_REPLACE on RTM_NEWQDISC.
async fn atomic_replace(conn: &Connection<Route>, qdisc: &DeclaredQdisc) -> Result<()> {
    // At its declared handle, or `1:` for a classful kind (#514). An
    // fq_codel goes with `flows`: `replace_qdisc` leaves it out of a change
    // and recreates the qdisc when the live table differs (#596).
    let handle = qdisc.effective_handle();
    let root = crate::TcHandle::ROOT;
    let dev = qdisc.dev.as_str();
    match &qdisc.qdisc_type {
        QdiscSpec::Ingress | QdiscSpec::Clsact => unreachable!("handled by replace_qdisc"),
        QdiscSpec::KernelDefault => conn.del_qdisc_if_exists(dev, root).await.map(drop),
        spec => conn.replace_qdisc_full(dev, root, handle, spec).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::types::LinkState;

    fn link(link_type: DeclaredLinkType, address: Option<[u8; 6]>) -> DeclaredLink {
        DeclaredLink {
            name: "l0".into(),
            link_type,
            state: LinkState::Unchanged,
            mtu: None,
            master: crate::netlink::config::MasterSpec::Unmanaged,
            address,
            attrs: Default::default(),
            bridge: None,
            port: None,
        }
    }

    fn netkit(mode: Option<crate::netlink::link::NetkitMode>) -> DeclaredLinkType {
        DeclaredLinkType::Netkit {
            peer: "l1".into(),
            mode,
            primary_policy: None,
            peer_policy: None,
            scrub: None,
            peer_scrub: None,
        }
    }

    /// A MAC on a kind with no hardware address is refused by name; on
    /// any other kind, or with no MAC declared, the check passes.
    #[test]
    fn a_mac_on_an_l3_only_kind_is_refused() {
        use crate::netlink::link::NetkitMode;
        const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

        // `validate()` runs this check now (#518), before anything changes.
        let why = link(DeclaredLinkType::Ovpn, Some(MAC))
            .unaddressable_mac()
            .expect("ovpn has no MAC");
        assert!(why.contains("ovpn"), "{why}");
        for mode in [None, Some(NetkitMode::L3)] {
            let why = link(netkit(mode), Some(MAC))
                .unaddressable_mac()
                .expect("L3 netkit has no MAC");
            assert!(why.contains("L2"), "{why}");
        }

        let l2 = link(netkit(Some(NetkitMode::L2)), Some(MAC));
        assert!(l2.unaddressable_mac().is_none());
        let vrf = link(DeclaredLinkType::Vrf { table: 10 }, Some(MAC));
        assert!(vrf.unaddressable_mac().is_none());
        assert!(
            link(DeclaredLinkType::Ovpn, None)
                .unaddressable_mac()
                .is_none()
        );
    }
}
