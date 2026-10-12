//! tc filter command implementation.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use nlink::{
    Error, EthProto, FilterPriority, TcHandle,
    netlink::{
        Connection, Result, Route,
        filter::{
            BasicFilter, BpfFilter, CgroupFilter, FilterConfig, FlowFilter, FlowerFilter, FwFilter,
            MatchallFilter, RouteFilter, RsvpFilter, TcindexFilter, U32Filter,
        },
        messages::TcMessage,
        types::tc::tc_handle,
    },
    output::{OutputFormat, OutputOptions, print_items},
};

#[derive(Args)]
pub struct FilterCmd {
    #[command(subcommand)]
    action: Option<FilterAction>,
}

#[derive(Subcommand)]
enum FilterAction {
    /// Show filters.
    Show {
        /// Device name.
        dev: String,

        /// Parent qdisc/class. When omitted, filters are listed across
        /// *all* parents (root, ingress, clsact, …) — real `tc filter
        /// show dev X` behaviour. Pass `--parent root` to narrow.
        #[arg(long)]
        parent: Option<String>,

        /// Protocol (ip, ipv6, all, etc.).
        #[arg(long)]
        protocol: Option<String>,

        /// Priority/preference.
        #[arg(long)]
        prio: Option<u16>,
    },

    /// List filters (alias for show).
    #[command(visible_alias = "ls")]
    List {
        /// Device name.
        dev: String,
    },

    /// Add a filter.
    Add {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter handle (e.g. 800::1).
        #[arg(long)]
        handle: Option<String>,

        /// Chain index (tc(8) `chain N`).
        #[arg(long)]
        chain: Option<u32>,

        /// Filter type (u32, flower, basic, etc.).
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Delete a filter.
    Del {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long)]
        protocol: Option<String>,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: Option<String>,
    },

    /// Replace a filter.
    Replace {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter handle (e.g. 800::1).
        #[arg(long)]
        handle: Option<String>,

        /// Chain index (tc(8) `chain N`).
        #[arg(long)]
        chain: Option<u32>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },

    /// Change a filter.
    Change {
        /// Device name.
        dev: String,

        /// Parent qdisc/class.
        #[arg(long, default_value = "root")]
        parent: String,

        /// Protocol.
        #[arg(long, default_value = "ip")]
        protocol: String,

        /// Priority.
        #[arg(long)]
        prio: Option<u16>,

        /// Filter handle (e.g. 800::1).
        #[arg(long)]
        handle: Option<String>,

        /// Chain index (tc(8) `chain N`).
        #[arg(long)]
        chain: Option<u32>,

        /// Filter type.
        #[arg(name = "TYPE")]
        kind: String,

        /// Type-specific parameters.
        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

impl FilterCmd {
    pub async fn run(
        self,
        conn: &Connection<Route>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        match self
            .action
            .unwrap_or(FilterAction::List { dev: String::new() })
        {
            FilterAction::Show {
                dev,
                parent,
                protocol,
                prio,
            } => Self::show(conn, &dev, parent.as_deref(), protocol.as_deref(), prio, format, opts)
                .await,
            FilterAction::List { dev } => {
                Self::show(conn, &dev, None, None, None, format, opts).await
            }
            FilterAction::Add {
                dev,
                parent,
                protocol,
                prio,
                handle,
                chain,
                kind,
                params,
            } => {
                dispatch_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    handle.as_deref(),
                    chain,
                    &kind,
                    &params,
                    FilterVerb::Add,
                )
                .await
            }
            FilterAction::Del {
                dev,
                parent,
                protocol,
                prio,
                kind: _,
            } => {
                let parent_t = parent.parse::<TcHandle>().map_err(|e| {
                    Error::invalid_message(format!("tc filter del: invalid parent `{parent}`: {e}"))
                })?;
                match (protocol.as_deref(), prio) {
                    // Full lookup tuple → delete exactly that filter.
                    (Some(proto_str), Some(p)) => {
                        let proto = parse_protocol(proto_str)?;
                        conn.del_filter(dev.as_str(), parent_t, proto, FilterPriority::new(p))
                            .await
                    }
                    // Bare parent → flush every filter on that parent
                    // (tc(8) `tc filter del dev X parent 1:`).
                    (None, None) => conn.flush_filters(dev.as_str(), parent_t).await,
                    // A half-specified tuple is ambiguous: which filter?
                    // Reject rather than guess (strict-parse contract).
                    _ => Err(Error::invalid_message(
                        "tc filter del: specify both --protocol and --prio to delete one \
                         filter, or neither to flush all filters on the parent"
                            .to_string(),
                    )),
                }
            }
            FilterAction::Replace {
                dev,
                parent,
                protocol,
                prio,
                handle,
                chain,
                kind,
                params,
            } => {
                dispatch_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    handle.as_deref(),
                    chain,
                    &kind,
                    &params,
                    FilterVerb::Replace,
                )
                .await
            }
            FilterAction::Change {
                dev,
                parent,
                protocol,
                prio,
                handle,
                chain,
                kind,
                params,
            } => {
                dispatch_filter(
                    conn,
                    &dev,
                    &parent,
                    &protocol,
                    prio,
                    handle.as_deref(),
                    chain,
                    &kind,
                    &params,
                    FilterVerb::Change,
                )
                .await
            }
        }
    }

    async fn show(
        conn: &Connection<Route>,
        dev: &str,
        parent: Option<&str>,
        protocol_filter: Option<&str>,
        prio_filter: Option<u16>,
        format: OutputFormat,
        opts: &OutputOptions,
    ) -> Result<()> {
        if dev.is_empty() {
            return Err(nlink::netlink::Error::invalid_message(
                "device name required",
            ));
        }

        // Resolve dev→ifindex over netlink (RTM_GETLINK in the
        // connection's netns), not the sysfs `/sys/class/net` read —
        // the latter is wrong inside a foreign netns.
        let ifindex = conn
            .get_link_by_name(dev)
            .await?
            .ok_or_else(|| {
                nlink::netlink::Error::invalid_message(format!("device not found: {dev}"))
            })?
            .ifindex();

        // When `--parent` is omitted, list filters across *all* parents
        // (root, ingress, clsact, …) — matching `tc filter show dev X`.
        // A `--parent <handle>` narrows the dump to that one parent.
        let parent_handle = parent
            .map(|p| {
                tc_handle::parse(p)
                    .map(nlink::TcHandle::from_raw)
                    .ok_or_else(|| {
                        nlink::netlink::Error::invalid_message(format!("invalid parent: {}", p))
                    })
            })
            .transpose()?;

        let proto_filter = protocol_filter.map(parse_protocol).transpose()?;

        // The library's per-device dumps: a filter dump has to name the
        // device (and a hook, for ingress/clsact), so the bare
        // RTM_GETTFILTER this sent came back empty and `filter show` never
        // printed a filter.
        let all_filters: Vec<TcMessage> = match parent_handle {
            Some(parent) => conn.get_filters_by_parent_index(ifindex, parent).await?,
            None => conn.get_filters_by_index(ifindex).await?,
        };

        // Filter results
        let filters: Vec<_> = all_filters
            .into_iter()
            .filter(|f| {
                // Filter by interface
                if f.ifindex() != ifindex {
                    return false;
                }
                // Filter by parent (only when one was requested)
                if let Some(parent_handle) = parent_handle
                    && f.parent() != parent_handle
                {
                    return false;
                }
                // Filter by protocol if specified
                if let Some(proto) = proto_filter
                    && f.protocol() != proto
                {
                    return false;
                }
                // Filter by priority if specified
                if let Some(prio) = prio_filter
                    && f.priority() != prio
                {
                    return false;
                }
                true
            })
            .collect();

        print_items(&filters, format, opts, filter_to_json, print_filter_text)?;

        Ok(())
    }
}

/// Verb tag for `try_typed_filter` — picks add/replace/change at the
/// `Connection::*_filter_full` callsite.
#[derive(Clone, Copy)]
enum FilterVerb {
    Add,
    Replace,
    Change,
}

/// Typed dispatch for every filter kind nlink models. Unknown
/// kinds error cleanly with a recognised-kinds list; there's no
/// silent fallback to a looser legacy parser anymore.
#[allow(clippy::too_many_arguments)] // args mirror the tc(8) CLI surface; bundling into a struct would just add ceremony
async fn dispatch_filter(
    conn: &Connection<Route>,
    dev: &str,
    parent: &str,
    protocol: &str,
    prio: Option<u16>,
    handle: Option<&str>,
    chain: Option<u32>,
    kind: &str,
    params: &[String],
    verb: FilterVerb,
) -> Result<()> {
    let parent = parent
        .parse::<TcHandle>()
        .map_err(|e| Error::invalid_message(format!("tc filter: invalid parent `{parent}`: {e}")))?;
    let proto = parse_protocol(protocol)?;
    let priority = FilterPriority::new(prio.unwrap_or(0));

    // Strict: a present-but-unparseable handle is an error, never a
    // silently-dropped filter (see the CLAUDE.md strict-parse contract).
    let handle = match handle {
        None => None,
        Some(h) => Some(h.parse::<TcHandle>().map_err(|e| {
            Error::invalid_message(format!("tc filter: invalid handle `{h}`: {e}"))
        })?),
    };

    let refs: Vec<&str> = params.iter().map(String::as_str).collect();

    macro_rules! dispatch {
        ($Cfg:ident) => {{
            // Bind through the ParseParams trait so the dispatcher's
            // contract is type-checked, not just convention.
            let mut cfg = <$Cfg as nlink::ParseParams>::parse_params(&refs)?;
            if let Some(chain) = chain {
                nlink::netlink::filter::FilterConfig::set_chain(&mut cfg, chain);
            }
            run_typed_filter(conn, dev, parent, handle, proto, priority, cfg, verb).await
        }};
    }
    match kind {
        "flower" => dispatch!(FlowerFilter),
        "matchall" => dispatch!(MatchallFilter),
        "fw" => dispatch!(FwFilter),
        "route" => dispatch!(RouteFilter),
        "bpf" => dispatch!(BpfFilter),
        "cgroup" => dispatch!(CgroupFilter),
        "flow" => dispatch!(FlowFilter),
        "u32" => dispatch!(U32Filter),
        "basic" => dispatch!(BasicFilter),
        "tcindex" => dispatch!(TcindexFilter),
        "rsvp" | "rsvp6" => dispatch!(RsvpFilter),
        other => Err(Error::invalid_message(format!(
            "tc filter: unknown kind `{other}` (recognised: flower, matchall, fw, route, bpf, cgroup, flow, u32, basic, tcindex, rsvp, rsvp6)"
        ))),
    }
}

#[allow(clippy::too_many_arguments)] // args mirror the tc(8) CLI surface
async fn run_typed_filter<C: FilterConfig>(
    conn: &Connection<Route>,
    dev: &str,
    parent: TcHandle,
    handle: Option<TcHandle>,
    proto: EthProto,
    priority: FilterPriority,
    cfg: C,
    verb: FilterVerb,
) -> Result<()> {
    match verb {
        FilterVerb::Add => {
            conn.add_filter_full(dev, parent, handle, proto, priority, cfg)
                .await
        }
        FilterVerb::Replace => {
            conn.replace_filter_full(dev, parent, handle, proto, priority, cfg)
                .await
        }
        FilterVerb::Change => {
            conn.change_filter_full(dev, parent, handle, proto, priority, cfg)
                .await
        }
    }
}

/// A protocol as tc(8) takes it: a name or a number (`EthProto`'s
/// `FromStr` reads it as iproute2's `ll_proto_a2n` does).
fn parse_protocol(s: &str) -> Result<EthProto> {
    s.parse()
}

/// Convert a TcMessage to JSON representation for filter.
fn filter_to_json(filter: &TcMessage) -> serde_json::Value {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    let mut obj = serde_json::json!({
        "dev": dev,
        "kind": filter.kind().unwrap_or(""),
        "parent": filter.parent().to_string(),
        "protocol": filter.protocol().to_string(),
        "pref": filter.priority().as_u16(),
    });

    if !filter.handle().is_unspec() {
        obj["handle"] = serde_json::json!(format!("{:x}", filter.handle_raw()));
    }

    if let Some(chain) = filter.chain() {
        obj["chain"] = serde_json::json!(chain);
    }

    if let Some(bpf) = filter.bpf_info() {
        let mut bpf_obj = serde_json::Map::new();
        if let Some(id) = bpf.id {
            bpf_obj.insert("id".into(), serde_json::json!(id));
        }
        if let Some(ref name) = bpf.name {
            bpf_obj.insert("name".into(), serde_json::json!(name));
        }
        if let Some(tag) = bpf.tag_hex() {
            bpf_obj.insert("tag".into(), serde_json::json!(tag));
        }
        bpf_obj.insert("direct_action".into(), serde_json::json!(bpf.direct_action));
        obj["bpf"] = serde_json::Value::Object(bpf_obj);
    }

    obj
}

/// Print filter in text format.
fn print_filter_text(
    w: &mut io::StdoutLock<'_>,
    filter: &TcMessage,
    _opts: &OutputOptions,
) -> io::Result<()> {
    let dev = nlink::util::get_ifname_or_index(filter.ifindex());

    write!(
        w,
        "filter parent {} protocol {} pref {} {} ",
        filter.parent(),
        filter.protocol(),
        filter.priority(),
        filter.kind().unwrap_or("")
    )?;

    if let Some(chain) = filter.chain() {
        write!(w, "chain {} ", chain)?;
    }

    if !filter.handle().is_unspec() {
        write!(w, "handle {:x} ", filter.handle_raw())?;
    }

    write!(w, "dev {}", dev)?;

    // Show BPF program info if present
    if let Some(bpf) = filter.bpf_info() {
        if let Some(ref name) = bpf.name {
            write!(w, " [{name}]")?;
        }
        if let Some(id) = bpf.id {
            write!(w, " id {id}")?;
        }
        if let Some(tag) = bpf.tag_hex() {
            write!(w, " tag {tag}")?;
        }
        if bpf.direct_action {
            write!(w, " direct-action")?;
        }
    }

    writeln!(w)?;

    Ok(())
}
