# Vandal UAT redesign

Status: current-inventory projection, persistent Explore workspace, and the draft-review workflow are deployed. See [scan-drafts.md](scan-drafts.md) for the current composer workflow and its remaining limitations. Per-tool full pages and aesthetic revisions remain later work.

For the verified remote release, validation results, backup paths, and remaining work, see [uat-handoff.md](uat-handoff.md).

## Problem

The current UI exposes accumulated evidence as if it were the current inventory. Hostnames inherit services from associated IPs across retained relationships; ports are grouped by observation owner as well as protocol and number. Separate sources generate separate CVE review items. These choices preserve evidence but produce duplicate rows, stale associations, and inconsistent counts.

The redesign needs one current inventory projection derived from immutable evidence. Results, facets, counts, host panels, maps, and exports should consume that same projection.

## Vocabulary and hierarchy

```text
Project
  Host (stable internal ID; hostname displayed, IP fallback)
    Address validation and history
    Current services (protocol + port)
      Individual address observations / source evidence
    Vulnerabilities (one entry per CVE per host)
      Affected services, source claims, analyst decision
    Other analyst items
    Evidence history
```

- A host name is the operator-facing identity, not a mutable database primary key. Preserve a stable internal ID so annotations, bookmarks, exclusions, and findings survive naming changes.
- Different hostnames sharing an IP are not automatically merged. An IP scan does not establish that every virtual host exposes the same application.
- IP-only observations remain unattributed until evidence establishes the relationship. PTR names alone should not silently rename or merge hosts.
- Show one primary address in the host row, with a `+N addresses` indicator when necessary. Retain the complete most recently validated A/AAAA answer set.
- Multiple simultaneous DNS addresses are valid, not automatically conflicting. RFC 2181 sections 5 and 5.4 describe complete resource record sets: https://www.rfc-editor.org/rfc/rfc2181.html#section-5
- Removed addresses belong in history. A validation failure leaves the last successful mapping visible with a stale/unvalidated label; it does not certify the old mapping as current or overwrite it with an empty answer.

## Current-state rules

1. Analyst confirmation governs vulnerability status. A source claim never confirms, unconfirms, or deletes an analyst decision.
2. For matching subjects and attributes, direct active evidence takes precedence over passive evidence. Resolve ties by observation time, then deterministic source-record identity. Import time is a fallback clearly recorded as such.
3. Active evidence only supersedes what it measured. A failed or partial scan cannot imply closed ports, resolved vulnerabilities, or absent services for untested items.
4. Show the latest applicable active result for each current service. Closed or filtered results replace an earlier open result for that same endpoint.
5. Passive fallback is visible only where active evidence is absent, with its provenance explicit. The operator's Hide passive preference removes fallback claims consistently from results and facets.
6. Superseded passive and active observations remain accessible under History, with source, timestamp, and the reason they no longer supply the current value.
7. When a hostname's address set changes, evidence for removed addresses becomes historical for that hostname. Do not copy banners or CVE claims from an old address to a newly associated address.
8. Derive the current projection from a consistent database read after ingestion. Recompute sidebar counts from the same projection and filter expression. No destructive identity migration or stored projection backfill is required.

## Deduplication

- One default result row per host.
- One service row per protocol/port under a host; expand it to inspect distinct address-specific observations. Different banners remain separate evidence, not an invented combined service.
- One vulnerability entry per host/CVE. Multiple scanners add claims and evidence to that entry. Different affected services nest underneath it.
- Keep manual non-CVE investigation items independent unless the operator explicitly links or merges them.
- Preserve conflicting analyst decisions for review during migration instead of selecting one silently.
- Label counts by unit: hosts, distinct addresses, current open services, unique CVE IDs, or affected host/CVE pairs. Avoid a generic endpoint count that mixes URLs and transport services.

## Reactive browsing

- Keep Overview as the landing view and New scan readily accessible, as previously requested.
- Use one persistent Explore workspace. Hosts, domains, web inventory, and vulnerabilities become views within it; selection and filters survive opening and closing a host panel.
- Group vulnerability browsing by host, with unassigned analyst items retained in a separate group. An optional inverse CVE-to-host grouping remains future work.
- Offer 25/50/100 rows per page and Load more. Update the list in place; preserve scroll, current selections, sorting, expanded rows, and the host panel.
- Store navigable state in the URL so refresh, bookmarks, and back/forward remain useful. Changing the URL should not rebuild the entire workspace.
- Share the filter model across result rows, sidebar counts, and exports. Label empty and stale states explicitly.
- For live updates, update affected rows without moving the user's scroll position; show a refresh indicator when applying a new sort would move rows under the pointer.

## Scan UX feedback (separate workstream)

Record the following UAT requests separately from the inventory migration:

- Generate a reviewable draft independently of optional inventory/DNS enrichment. Show draft-generation errors separately from execution validation errors.
- Preserve the target identifier the operator entered in draft displays and audit records.
- Retain warnings, draft revisions, execution status, output artifacts, and failure reasons in the timeline.
- Treat imported DNS validation results as inventory evidence; keep address synchronization distinct from opening a scan form.
- Per-tool composer layouts can be designed after the inventory behavior stabilizes.

This plan does not add unrestricted shell execution or remove target/scope execution controls. Editable non-executing drafts and imported results can support review without such changes.

## Delivery order

1. Build and test the current-state projection alongside the existing database. Produce a read-only comparison report for representative hosts before changing UI defaults.
2. Derive stable host/CVE group keys from existing asset IDs and CVE IDs; preserve original records and analyst decisions without merging database rows.
3. Switch Explore and host panels to the projection, then align facets, counts, maps, and exports.
4. Replace full-list redraws with persistent reactive list state, per-page controls, and Load more.
5. Review the separate scan UX workstream and later per-tool layouts.

## Implementation and validation

- `vandal/projection.py` derives current address sets, groups current services by transport/port, and groups CVE claims by host. Original asset IDs, review item IDs, records, and decisions remain intact.
- `/hosts`, `/host-vulnerabilities`, `/hosts-export`, and the current dashboard share the projection. Legacy evidence and scan APIs remain available.
- `host-workspace.js` retains Explore view state, selected rows, filters, and host popouts. Lists support 25/50/100 rows and Load more. Incoming evidence shows a refresh indicator instead of moving rows under the pointer.
- DNS evidence is consumed from imports. The second pass adds a host-level Sync DNS entry point into the existing user-reviewed DNS validator. Address validity is shown explicitly, including failed validation and expired TTLs; scan execution controls are preserved.
- The read-only comparison used a consistent backup of the remote database at `/home/ubuntu/vandal-uat-backup-20260910T213816Z`. It reduced 6,044 hostname service rows to 3,156 distinct service groups across the same retained evidence; stable IDs and database integrity passed.
- Acceptance tests cover replaced address mappings, multiple current addresses, active/passive precedence, retained evidence, analyst decisions, facets, exclusions, exports, and pagination. Browser checks cover desktop/mobile layout, selection, view restoration, Load more, grouped services/CVEs, and host popouts.

Source rollback restores the previous Python/static files and restarts the service. This change does not require a database rollback.

## Acceptance examples

- Five observations of TCP/443 display one service row and five accessible evidence records.
- Two IPs with conflicting TCP/443 banners display one expandable service group with two attributable observations.
- Three sources reporting one host/CVE display one vulnerability with three source claims.
- A hostname that moves from address A to B does not inherit A's old service inventory as B's current state.
- A valid two-address DNS answer does not alternate identity based on answer order.
- A newer explicit closed observation overrides an older passive open claim, which remains in History.
- A partial scan touching TCP/443 does not silently close untested TCP/22.
- Importing an old artifact does not replace a newer observed state merely because it was uploaded later.
- Confirmed vulnerabilities survive deduplication, passive hiding, and source archive/restore according to the existing visibility rules.
- Every visible sidebar count reproduces the corresponding filtered results.
- Opening a host, changing page size, and loading more results preserve the surrounding Explore state.
