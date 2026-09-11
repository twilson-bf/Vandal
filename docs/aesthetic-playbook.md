# Vandal interface playbook

Status: historical planning document for the restrained terminal pass. The approved fantasy-tech direction supersedes this file and is defined in [design-bible.md](design-bible.md). Keep this document as the record of the earlier design reasoning; agents should use the design bible as the canonical implementation contract.

## Premise

Vandal should feel like an operator's view into a live assessment system: specific, dense, slightly unfamiliar, and completely usable. The fiction comes from how real data is framed and manipulated. It does not come from hacker slogans, fake boot text, random hexadecimal strings, neon borders, or decorative glitches.

The primary reference is Marathon's Codex: a calm reading plane inside a more atmospheric system shell. Original Marathon terminals contribute terse connection metadata, explicit navigation hints, and document-like information flow. Alien: Isolation contributes the idea that an interface feels diegetic when it behaves like a particular machine. Vandal remains faster and clearer because it is a working assessment tool.

## Core rules

### 1. Make the data the fiction

Use real engagement names, asset identifiers, observation times, scan states, source tools, resolver status, scope state, and evidence counts as the system language. A hostname and its current address should feel like a record being inspected, not content placed inside a generic product card.

Do not add invented system messages unless they describe a real state. Use `DNS UNVALIDATED`, `LAST ACTIVE 14:13 UTC`, or `3 SOURCES`; do not use `ACCESS GRANTED`, `UPLINK ESTABLISHED`, or similar stage dressing.

### 2. Separate the shell from the reading plane

The shell is dark, compact, and atmospheric. It contains engagement context, navigation, global state, and the primary scan action. The reading plane contains the current task and should be quiet enough for sustained use.

Keep texture in the shell and empty margins. Do not lay a strong scanline treatment over body text. Data surfaces use near-black and warm gray rather than a stack of bright silver cards.

### 3. Use typography as structure

Fraktion Mono is the default interface face. Size, weight, case, and spacing create hierarchy:

- Page identity: 22–26px, compact, used once.
- Record identity: 15–18px, normal case, allowed to wrap.
- Section and column labels: 10–11px, uppercase, tracked slightly.
- Operational data: 12–13px, high contrast.
- Metadata: 10–11px, lower contrast, never too faint to read.

The display face is reserved for a page title or major count. It should not compete with hostnames, commands, or evidence.

### 4. Color carries state

- Orange identifies the current locus of action: the primary action, current workspace, selected record, or live progress.
- Blue belongs to geographic and network context, including the globe.
- Red is reserved for confirmed vulnerabilities and blocking failures.
- Amber communicates warnings or unvalidated state.
- Green communicates successful completion or actively verified open state.
- Warm white and gray carry ordinary information.

One region should rarely contain more than one strong accent. Selection may use a pale inverse field with dark text, echoing the Codex reference. Avoid colored left rails, glowing outlines, rainbow severity decoration, and orange applied to arbitrary first cards.

### 5. Prefer planes, rules, and registers over cards

Use flat sections, restrained surface shifts, aligned columns, and deliberate empty space. Separate groups through spacing and background value rather than hairline rules. Rounded cards are reserved for transient overlays or objects that truly behave as movable units. Controls use small radii or squared corners.

Rows should read like records in a ledger. Repeated panels should not restate the same status. Empty sections collapse into a short status line.

### 6. Density comes from removing repetition

Reduce padding before reducing text size. Keep one primary line and one or two secondary lines per host. Suppress repeated zero states such as `0 confirmed`, `0 potential`, and `No current open services` when they convey no useful distinction.

At 1600×1000, Explore should show at least six useful host records before scrolling. At narrow widths, filters move into a drawer so the first results remain above the fold.

### 7. Reveal depth in place

The operator should retain spatial context while opening a host, service, CVE, scan, or source record. Use drawers, inline expansion, and anchored detail panes. Avoid page changes for inspection.

The host dossier has one canonical vulnerability register, sorted by severity. A small confirmed-vulnerability summary may remain pinned near the identity block, but it must not duplicate the full record list. Service and evidence histories expand beneath their owning row.

### 8. Motion reports causality

Motion is limited to opening a drawer, expanding a record, updating a running job, or moving between map focus states. Use short, direct transitions. No ambient jitter, fake terminal typing, boot sequences, looping glitches, or parallax.

### 9. Controls should resemble instruments

Buttons use direct verbs: `Scan`, `Import`, `Sync DNS`, `Add to scope`. Frequent actions remain visible; tuning controls and rare fields sit behind an `Advanced` disclosure. Command previews look like editable command buffers with warnings adjacent to the exact affected argument.

Use familiar controls where speed matters. The atmosphere should never make ports, services, severity, selection, or navigation harder to distinguish.

## Screen application

### Shell and navigation

- Reduce the top bar to roughly 50px and narrow the navigation rail.
- Keep engagement identity, activity state, and `New scan` persistently visible.
- Let Explore own Hosts, Domains, Web, and Vulnerabilities as local modes; remove their duplicate global navigation entries.
- Group Scan data, Imports, and Timeline under an evidence/activity region without hiding frequent destinations in deep menus.
- Place the passive-data preference with search and evidence controls instead of floating beside every page title.

### Overview

- Replace large metric cards with a compact operational register.
- Keep the blue globe and meaningful recent activity high on the page.
- Summarize long target lists as a primary target plus a count, expandable in place.
- Collapse empty job regions rather than preserving large vacant panels.

### Explore

- Treat search, result identity, sort, selection, and pagination as one compact command strip.
- Keep facets available without allowing them to dominate the viewport.
- Render hosts as aligned records: hostname, current address and validation, open services, vulnerability state, and last active evidence.
- Preserve complete hostnames with a controlled two-line wrap; do not introduce ambiguous ellipses.

### Host dossier

- Put identity, current address, DNS state, location, sources, and last observation into a compact header register.
- Place current services and vulnerabilities in dense, independently expandable columns.
- Make confirmed vulnerabilities immediately visible, using red only when at least one exists.
- Collapse address, scan, and observation history until requested.

### Scans

- Replace the large tool-card gallery with a compact tool selector and visible job queue.
- Put essential target and profile controls first; put tuning flags in grouped disclosures.
- Give the editable command buffer visual priority before execution.
- Keep warnings specific and adjacent to the setting that caused them.

## Explicit exclusions

Do not use hairline separators, neon wireframe borders, permanent glow, colored left-edge highlights, glass panels, gradient-filled cards, oversized rounded rectangles, arbitrary color splashes, dashboard slogans, fake system copy, fake noise in live data, or icons that require hover text to distinguish their meaning.

The interface may feel old, proprietary, or slightly severe. It must never feel slow, illegible, or theatrical at the expense of evidence.

## First-pass acceptance

- Existing behavior, URLs, filters, and keyboard interactions still work.
- Explore exposes six or more useful records at 1600×1000 and shows results above the fold at 768px.
- A host with many ports and CVEs remains scannable without duplicated vulnerability lists.
- Confirmed vulnerability red, warning amber, open-state green, and map blue retain distinct meanings.
- Text remains readable with texture and scanline effects disabled.
- Overview, Explore, host detail, and Scans look like parts of one operating system.

## Reference basis

- Marathon Codex reference supplied by the user: dark system shell, restrained inverse selection, compact context labels, and a calm document plane.
- Original Marathon terminals: terse connection metadata, explicit timestamps, document navigation, and operational language.
- Michael Rigley's Marathon interface work: graphic systems derived from the world art direction, structured color blocking, and intentionally authored type.
- Jon McKellan on Alien: Isolation: a consistent machine concept, deliberate separation between easy overlays and in-world interfaces, and analogue treatment applied to static presentation rather than live information.
