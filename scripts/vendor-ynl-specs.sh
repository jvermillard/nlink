#!/usr/bin/env bash
# #167 — fetch the kernel's YNL netlink specs at a release tag into
# third_party/ynl-specs/, and record their provenance in SOURCE.
#
# usage: scripts/vendor-ynl-specs.sh v7.2
#
# The specs are what scripts/audit-uapi-constants.sh checks nlink's
# constants against, alongside the build host's headers. They are vendored,
# not fetched in CI, so the gate is reproducible offline and a spec can only
# change in a reviewed commit. SOURCE pins each file's sha256; the audit
# refuses a spec whose hash does not match, so nobody can edit one to
# silence a failure.
set -euo pipefail

TAG="${1:?usage: $0 <kernel tag, e.g. v7.2>}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
DEST="$REPO_ROOT/third_party/ynl-specs"
BASE="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain"

# nftables and conntrack are left out: their specs describe nf_tables.h and
# nfnetlink_conntrack.h without values and omit attributes (pads), so their
# implicit numbering drifts from the headers. Those headers are present on
# every host nlink supports, and the header audit checks them in full.
SPECS=(rt-link rt-addr rt-route rt-neigh rt-rule tc wireguard ethtool devlink dpll
       netdev mptcp_pm net_shaper ovpn nl80211 nlctrl)

COMMIT="$(git ls-remote https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
    "refs/tags/$TAG^{}" | cut -f1)"
[[ -n "$COMMIT" ]] || { echo "no such tag: $TAG" >&2; exit 1; }

mkdir -p "$DEST"
for spec in "${SPECS[@]}"; do
    curl -sSf -o "$DEST/$spec.yaml" "$BASE/Documentation/netlink/specs/$spec.yaml?h=$TAG"
done
curl -sSf -o "$DEST/LICENSE.BSD-3-Clause" "$BASE/LICENSES/preferred/BSD-3-Clause?h=$TAG"

{
    echo "# The kernel's YNL netlink specs, vendored by scripts/vendor-ynl-specs.sh."
    echo "tag $TAG"
    echo "commit $COMMIT"
    (cd "$DEST" && sha256sum ./*.yaml | sed 's| \./| |')
} > "$DEST/SOURCE"
echo "vendored ${#SPECS[@]} specs from $TAG ($COMMIT) into $DEST"
