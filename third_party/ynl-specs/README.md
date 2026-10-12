# Kernel YNL netlink specs (vendored)

The Linux kernel describes its netlink families in YAML specs under
`Documentation/netlink/specs/`. These are copies of 16 of them, at the release
named in `SOURCE`, fetched by `scripts/vendor-ynl-specs.sh`.

**What they are for.** `scripts/audit-uapi-constants.sh` derives every
constant they define (attribute ids, commands, enum values) and checks nlink's
hand-written constants against them, alongside the build host's
`/usr/include/linux` headers (#167):

- A constant that both a spec and a header define must have the same value in
  both. A disagreement fails the build: it would mean the derivation is wrong,
  or a spec is. Known spec quirks are listed, with a reason each, in
  `scripts/audit-uapi-constants.ynl-quirks`.
- A constant that only a spec defines checks nlink too. That covers families
  newer than the host's headers, such as `ovpn` (6.16) and `net_shaper` (6.13)
  on a 6.12 host, and every constant after the host's kernel version.

Nothing here is built into the `nlink` crate. They are inputs to a CI check.

**Not vendored:** `nftables` and `conntrack`. Their specs describe
`nf_tables.h` and `nfnetlink_conntrack.h` without giving values, and they omit
attributes (pads), so their implicit numbering drifts from the headers. Those
headers are present on every host nlink supports, and the header audit checks
them in full.

**Provenance.** `SOURCE` records the kernel tag, its commit and each file's
sha256. The audit refuses a spec whose hash does not match, so a spec can only
change by re-running the vendoring script in a reviewed commit:

```text
scripts/vendor-ynl-specs.sh v7.2
```

**Licence.** Each spec carries `SPDX-License-Identifier: ((GPL-2.0 WITH
Linux-syscall-note) OR BSD-3-Clause)`. They are used here under BSD-3-Clause,
whose text, from the kernel's `LICENSES/preferred/BSD-3-Clause`, is in
`LICENSE.BSD-3-Clause`. The files are unmodified, so their copyright and SPDX
headers are kept.
