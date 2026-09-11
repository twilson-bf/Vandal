# vandal — external assessment platform design

Status: first working implementation available. This document retains the broader
design; README.md describes implemented capabilities and follow-on integrations.
Name: **vandal** (as in Vandal Blast). Project directory: `~/dev/vandal`.

The implemented workspace now follows a project-scoped host/service inventory model.
Overview remains the landing page; Explore supplies Shodan-style subset search and
facets with IP-first/hostname-first results. Domains is a dedicated discovery view.
Persistent host pages expose service summaries, observations, vulnerabilities,
relationships, scan history and notes. The global New scan action remains visible.
Original evidence is retained; summaries do not merge virtual-host claims into an IP.
See README.md for the supported search grammar and current coverage semantics.

## Purpose

A reusable operator workspace that joins discovery, port scans, service identification, and vulnerability observations into an explorable external attack surface. Separate engagements isolate client data. Kohler is the first dataset, not a hardcoded product assumption.

Primary workflow: create engagement → import scans → explore and correlate assets → select targets → run a scan profile → ingest results → compare changes and annotate evidence.

## Findings from local inputs

- LotusPetal uses dark chrome, silver-gray content panels with black text, condensed uppercase headings, monospace detail text, rounded cards, solid navigation highlights, and a subtle dot grid. Its current implementation uses top navigation and bundled fonts and map assets.
- Bill's EPT directory contains ten Nmap XML files with companion `.nmap` and `.gnmap` outputs; XML files 1, 3, and 5 fail complete-document parsing because they end prematurely.
- Five Nessus HTML reports are available; no `.nessus` export is present.
- Supplementary inputs include `discovered-ports.json`, `discovered-ports.csv`, a 597-line IP list, and a 153-line hostname list. The JSON metadata reports 748 port records across 64 hosts; this is source metadata, not a verified count of unique open endpoints.
- Hostname seeds include provider PTR names and cloud hostnames. Their presence must not imply ownership of the provider's registrable domain.
- No BBOT export is present yet. Its importer needs versioned fixtures, including older `data` and newer `data`/`data_json` representations.

## Interface

Use LotusPetal's visual language, adapted to a wider data workspace. Charcoal background `#141416`, silver panels `#C4C8CB`, black panel text, orange accent `#FF8A24`, lighter orange `#FFB066`, and restrained orange glow. Orange buttons use dark text. Severity retains independent labeled colors so brand orange does not imply risk. Reuse bundled open fonts with their license; do not depend on missing proprietary fonts.

Persistent top bar: engagement selector, global search, import action, job activity indicator. Navigation: Overview / Explore / Findings / Scan Data / Imports / Jobs / Scope.

| View | Behavior |
| --- | --- |
| Overview | Asset and coverage counts, open endpoint totals, service-identification coverage, findings by severity, latest imports, data-quality warnings, recent changes. Every metric opens the corresponding filtered explorer. |
| Explore | Shared filter state across table, geographic map, and domain tree. Optional focused relationship graph on an asset. |
| Asset detail | Full page and quick side drawer: names/IP relationships, endpoints, service evidence, web origins, findings, sources, history, tags, notes, scope attribution. |
| Findings | Broad investigation inbox for anything potentially interesting: unexpected services, new assets, ownership questions, scanner matches, unusual responses, and analyst hypotheses. Interest, workflow state, scanner severity, and analyst-confirmed vulnerability status are independent. |
| Scan Data | Browse every run and original record, including informational, negative, unknown and unparsed content; inspect structured fields, raw text, logs and artifacts, with links to correlated objects. |
| Imports | Multi-file drag/drop, format detection, preview, progress, warnings, duplicate detection, source artifacts, retry and reversible import removal. |
| Jobs | Profile configuration, concrete target preview and count, executable/arguments preview, run/cancel, progress, logs, artifacts and ingestion results. |
| Scope | Include/exclude domains, CIDRs and explicit assets; business labels, ownership evidence, unresolved attribution, exclusions with reasons. |

Explorer facets: country, region/city when available, ASN/provider, business/brand, registrable domain, hostname/subdomain, IPv4/IPv6/CIDR, port, transport, port state, service identity and evidence level, product/version, HTTP/TLS attributes when present, severity/CVE/plugin, source tool/run, first/last observation, scope status, tags and analyst status.

Filters combine across categories with AND and within a category with OR. Shareable URLs and saved views preserve filters, sorting, columns, and view mode. Server-side filtering, pagination and facet counts keep large datasets responsive. A country click updates the table; selecting a domain updates its IPs and endpoints. Filter semantics explicitly distinguish latest observations from historical matches.

Example: choose a country → narrow to a business → select TCP/443 → require probe-identified HTTPS → inspect related names and evidence → select endpoints for a follow-up profile.

Map locations describe IP infrastructure, not office locations or ownership. Unknown locations remain selectable and counted. Cluster markers; display location source, database date, and precision. Use a bundled world basemap and a local GeoIP/ASN database when configured; no automatic disclosure to a public geolocation API. Domain names inherit locations through observed resolution edges and may appear in multiple places.

Domain tree uses a versioned local Public Suffix List, including explicit handling of private suffixes. Provider hostnames remain visible as external relationships. Never infer organization ownership from a shared IP, certificate SAN, PTR record, or common suffix.

## Data model and reconciliation

Use normalized relational entities plus immutable source observations. An asset record is a convenient current view; the observations explain where each value came from.

| Entity | Identity and purpose |
| --- | --- |
| Engagement | Client boundary, membership, defaults, scope rules. |
| Artifact / Import | Original content hash, filename, format, parser version, status, warnings, ingestion time. Deduplication is engagement-scoped. |
| Scan run | Tool/version, actual scan timestamps, coverage, completion, source artifacts, optional originating job. |
| Hostname / IP | Canonical IDNA hostname or normalized IPv4/IPv6, scoped to engagement. Keep original spelling as evidence. |
| Relationship | DNS A/AAAA/CNAME, PTR, scanner hostname association, certificate mention; typed and timestamped, with provenance. |
| Endpoint | IP + transport + port; preserve domain-targeted endpoints without inventing an IP mapping. |
| Web origin | Scheme + hostname + effective port; separate virtual hosts even when they share an IP. URLs retain path/query evidence without unsafe over-normalization. |
| Observation | Source record locator, observed time, imported time, endpoint state, service/product/version, banner, structured tool metadata. |
| Finding instance | Plugin or source rule + appropriate asset/endpoint/origin; raw output, CVEs, CVSS versions/vectors, scanner severity, observation history. |
| Analyst assessment | Manual service verification, finding disposition, notes and attribution; author/time/reason independent of scanner output. |
| Job | Durable configuration, target snapshot, status, process lifecycle, timestamps, logs and artifacts. |

Service evidence is explicit: port-number hint, scanner probe identification, or analyst verification. Preserve Nmap `method`, `conf`, tunnel and product/version fields. A table lookup does not become a confirmed service; an open port alone says nothing definitive about its application. Conflicting observations remain visible. The UI's service filter offers both probe-identified and analyst-verified selections.

Preserve port states including `open|filtered`; do not count them as confirmed open. Keep liveness reasons so Nmap `-Pn` assumptions are not presented as evidence of reachability. Missing from a later scan does not mean closed, fixed or gone. Change views require compatible scan coverage and explicit evidence; incomplete scans cannot establish disappearance. Use actual observation times rather than upload order and label fallback/unknown times.

Exact reuploads are idempotent. Companion scan formats are associated when provenance supports it; prefer XML detail without counting `.nmap`, `.gnmap`, CSV and JSON representations as independent corroboration. Uncertain run matches remain explicit. An import can be removed from the derived view and aggregates rebuilt without erasing unrelated observations or analyst notes.

## Ingestion

All paths use the same pipeline: upload/CLI/job artifact → bounded staging → format sniffing → parser → normalized staging records → validation → transactional publication → aggregate refresh → UI event.

First-release adapters:

- Nmap XML: streaming parser; support complete files and recovery of fully closed host records from truncated files. Show partial status and discarded/incomplete tail counts. No invented closing data or completion time. Companions can add recoverable observations with their own provenance.
- Nmap `.gnmap` and `.nmap`: lower-fidelity fallback adapters with explicit limitations.
- Nessus `.nessus` XML: canonical structured adapter for future uploads.
- Nessus HTML: dedicated adapter for the five supplied reports' structure, extracting only present data. Preview fields and warn about omitted/unrecognized sections. Unsupported report layouts fail clearly, rather than silently producing empty success.
- BBOT JSON/JSONL: version-aware event normalization, preserving event ID/type, parent/module lineage, timestamps, tags and supported structured payloads. Unrecognized event types stay available in raw evidence with a warning/count.
- IP/domain TXT and mapped CSV; dedicated support for Bill's discovered-ports CSV/JSON. A seed list is inventory input, not proof that hosts are live or services are confirmed.

Original files remain immutable, stored outside web-served directories. Reports, banners and plugin output render as escaped text; do not embed uploaded HTML in the application's origin. Limit file/record sizes and reject external XML entity resolution. A small CLI supports bulk import of an existing folder without uploading files individually.

## Server and execution

Proposed stack: FastAPI/Uvicorn, SQLAlchemy with Alembic migrations, SQLite WAL, Jinja templates with HTMX and focused JavaScript for map/tree/table interactions. Local static assets; no Node build required. Use a D3-based world map consistent with LotusPetal. Start with indexed SQL and full-text search; no search cluster or graph database required.

`python run.py` starts the web service and a supervised worker process. SQLite persists job state; a single ingestion writer keeps transactions short. Worker jobs are leased and heartbeated; a restart marks interrupted work honestly and does not automatically repeat an active network scan. PostgreSQL/external workers are a later migration if actual concurrency warrants them.

Initial executable adapters: Nmap and BBOT; Nessus import support first. A future Nessus connector should use the installed product's supported API rather than assume Nessus is an ordinary shell scanner.

Scanner profiles supply structured arguments to subprocess execution with `shell=False`. Operator-editable profiles are validated per tool, not arbitrary web shell text. Jobs get isolated output directories, bounded concurrency, timeout/cancellation, output-size management, tool version capture and process-group cleanup. The UI shows installed/missing tool status and profile capabilities.

Targets come from explicit selections, validated input, or a saved-view snapshot. Resolve applicable domain targets and enforce include/exclude rules against the actual addresses at dispatch; exclude rules win. Keep shared-host boundaries visible. BBOT recursion obeys the chosen module profile and scope rules, with discovery output not automatically authorizing subsequent scans. No automatic scan on import. Clicking Run queues the reviewed job; no repetitive confirmation dialog.

Completed outputs auto-ingest. BBOT may publish complete JSONL events incrementally; an interrupted job can expose valid partial results, clearly labeled. Nmap's finalized artifact goes through the same recovery-aware importer. A failed command and a failed import are distinct statuses. Use server-sent events for progress and live refresh with reconnect/poll fallback.

Localhost binding by default. Bootstrap admin plus operator/viewer roles, engagement membership, authenticated artifact downloads, CSRF protection for cookie-authenticated mutations, and an audit trail. Server remains unprivileged; profiles requiring unavailable privileges show that limitation instead of elevating the web process.

## Build sequence and acceptance

1. **Foundation and real-data import:** schema/migrations, engagement, artifact pipeline, Nmap/Nessus/BBOT/list adapters, batch CLI, regression fixtures. Import Bill's files and reconcile source-derived counts; explicitly exercise the three truncated XML files.
2. **Exploration:** orange vandal shell, table/facets, domain tree, map, asset drawer, provenance, service evidence, findings, saved views and exports. Verify shared-IP virtual hosts, IPv6, unknown geography and conflicting observations.
3. **Dynamic workflow:** upload queue/progress, scan history/diffs, reversible import removal, Nmap/BBOT runner and automatic ingestion. Verify timeouts, cancellation, restart handling, scope exclusions and duplicate output handling using fixture executables and local test targets.
4. **Operational polish:** authorization boundaries, upload/rendering tests, backup/restore, installation docs and performance checks on real imports. Pin dependency/tool compatibility and record supported parser variants.

Completion means Bill's available data is explorable without requiring new exports; uploads update the existing engagement without duplicate assets; every displayed service/finding is traceable; partial sources remain visible; selected local test scans auto-ingest successfully; and map/domain/port/service filters agree on the underlying asset set.

No remote target scan is needed to build or test this application. App implementation and launch do not themselves start engagement scans.

## Decisions proposed for review

- Confirmed name/directory: vandal at `~/dev/vandal`.
- Deployment: local-first, small-team capable with engagement separation from the start.
- Delivery scope: imports and exploration first, followed by Nmap/BBOT job execution within the initial build.
- Geolocation: local database supplied/configured independently; unknown state until data is available.
- Focused asset relationships in v1; a global force-directed graph, scheduled rescans, and direct Nessus control deferred.

## Format references

- Nmap XML service identification semantics: https://nmap.org/book/output-formats-xml-output.html
- BBOT events: https://www.blacklanternsecurity.com/bbot/Stable/scanning/events/
- BBOT 3 migration: https://github.com/blacklanternsecurity/bbot/blob/stable/docs/migration/3.0_breaking_changes.md
- Nessus structured export: https://developer.tenable.com/docs/export-file-formats
- Nessus report templates: https://docs.tenable.com/nessus/10_10/Content/CreateAScanReport.htm

## Discovery and correlation revision — 2026-09-08

This section refines the earlier proposal. Remain in planning; do not implement the server until the tool/workflow plan is settled.

### Findings and complete scan browsing

Findings are broad items of interest, created manually from any record or suggested by transparent rules. Examples: a new hostname, unexpected RDP listener, unusual HTTP response, potentially stale DNS, ownership ambiguity, a scanner vulnerability claim, or a promising application. Each can link multiple assets and records across tools. Nothing is automatically promoted to an analyst-confirmed vulnerability.

Model an InterestItem separately from raw ToolResult and AnalystAssessment. Fields: title, category, explanation, priority, workflow state (new/reviewing/parked/dismissed), owner, tags, evidence links, optional analyst disposition and confirmed vulnerability reference. Scanner severity is retained on tool results; it does not determine interest priority or analyst confirmation. Existing FindingInstance terminology refers to tool-reported matches, not the product's broad Findings object.

Scan Data is a first-class browser: runs → records → nested fields/raw output. It includes informational plugins, NSE output, DNS answers, HTTP responses, errors, negative results, command logs, completion/coverage data and unmapped fields. Original bytes are downloadable. Large records are paginated or streamed with explicit truncation indicators; stored originals remain intact. Normalized search covers common fields; raw text search and tool-specific field inspection cover the remainder. Unsupported records remain visible, counted and attached to their source. Empty results, parser failure and incomplete artifacts must look different.

Every correlated value links to its contributing records; every raw record links back to the related entities. Preserve full data received; tools may not collect every possible response/body, so show acquisition limits rather than claim missing content exists.

### Proposed tool selection

User decision: assume no external data-service API accounts. The baseline must work with BBOT sources requiring no keys, public DNS resolvers and public registry/RIPEstat endpoints. Record unavailable sources, errors and rate limits so missing coverage is visible. Paid providers are optional future adapters, not dependencies or initial setup requirements.

| Capability | Initial choice | Role |
| --- | --- | --- |
| Passive subdomains | BBOT with a pinned passive subdomain preset | Collect CT, passive DNS and other enabled source observations. Preserve provider/module lineage. Explicitly inspect DNS/internal module behavior so passive collection does not silently become HTTP probing or brute forcing. |
| Independent DNS validation | dnsx, invoked separately for each configured resolver | Collect A/AAAA/CNAME and related DNS details independently of BBOT. Preserve answer sets, resolver, response code, raw response, query time and TTL where emitted. Separate wildcard tests. |
| DNS disagreement follow-up | Small dnspython adapter | Query authoritative servers and selected independent recursive resolvers explicitly; preserve full DNS messages and vantage metadata. Authoritative queries are a distinct validation action. |
| Company/resource discovery | RIR organization search (initially ARIN Whois-RWS, extensible to other RIRs), RDAP and RIPEstat | Company aliases → candidate registration entities → registered resources/ASNs → observed announced prefixes and origin ASNs. Registry allocation and BGP routing are separate evidence. |
| Network/service scans | Nmap | Port states and reasons, service-probe evidence, banners and selected script outputs. |
| Vulnerability scan ingestion | Nessus | All plugin data, including informational records. HTML and `.nessus` support; execution integration depends on available Nessus product/API. |
| Web inventory | ProjectDiscovery httpx | HTTP metadata, redirects, headers, technology hints and TLS metadata; retain requested host/SNI and actual connection address. |
| Visual inventory | gowitness | Screenshots with original URL/final URL, time, logs and captured metadata; browse a screenshot gallery in vandal. |
| Supplemental passive intelligence | Censys; additional providers depending on existing accounts | Independent host/web/certificate observations. Optional; the core pipeline works without paid services. |

Recommended selectable follow-ups: Katana for URL/endpoint discovery; TLSx for focused certificate collection or testssl.sh for deeper TLS checks; Nuclei for explicitly selected template packs. These add evidence and interests, not confirmed vulnerabilities. Pin template versions/hashes as well as tool versions. Avoid enabling overlapping collectors twice through both BBOT and standalone jobs; record underlying tool lineage when importing nested outputs.

Do not add another general subdomain enumerator or high-speed port scanner by default. Add one later only if coverage comparisons or measured throughput identify a gap. Discovery, DNS validation, web probes, screenshots, port scans and deeper checks are distinct job profiles with visible network behavior and resource budgets.

BGP is not a company-name directory or an ownership oracle. Name matches produce candidates with registry handles and evidence for review. Preserve registered holder, routing origin/operator and business attribution independently. Do not import an entire cloud provider ASN into client scope because one client hostname uses it. No automatic expansion of discovered prefixes into scans. Regional registration data must support non-ARIN resources through appropriate RIR adapters.

### Meaning of external domain/IP validation

Use independent public recursive DNS observations as the baseline interpretation of the request. A separate resolver invocation per provider gives accountable independent results; distributing a batch across a resolver pool does not establish agreement. Optionally add remote-vantage adapters later; a public resolver queried from this server is not equivalent to scanning from another country.

Validation status: independently corroborated, single-source, divergent answer sets, NXDOMAIN, NODATA, timeout/SERVFAIL, wildcard-suspected, or stale. Negative answers and transient failures remain distinct. A certificate or passive DNS record is historical/discovery evidence, not proof of current resolution. TTL informs freshness but does not establish continued validity. Scheduled or operator-requested rechecks create observations rather than overwrite old ones.

### Cross-scan object model

The durable abstraction is an **Asset**, implemented as a typed entity with a stable engagement-scoped ID, all source observations and explicit relationships. Types: hostname, IP, network prefix, ASN, web origin and certificate. Endpoints attach to network identities; applications can be optional analyst-defined groups of web origins and infrastructure. Group membership is a claim with evidence and history, not an automatic connected-component merge.

Canonical identities:

- hostname: normalized IDNA name, preserving source form; registrable-domain hierarchy is a separate relationship;
- IP: normalized address plus IPv4/IPv6 family;
- endpoint: address + transport + port;
- web origin: scheme + hostname + effective port; observed serving IPs are time-dependent relationships;
- certificate: SHA-256 fingerprint; shared certificate alone does not merge assets;
- prefix/ASN: normalized CIDR / ASN number.

Same canonical identity across scans automatically links to the same entity. Similar banners, certificates, provider labels and names create relatedness evidence, never identity equality. A hostname-targeted scanner result without an observed IP stays attached to the hostname/origin; today's DNS must not retroactively assign yesterday's scan to an IP.

Relations include resolves-to, aliases-to, reverse-name, serves-origin, presents-certificate, contained-in-prefix, announced-by, registered-to and attributed-to. Each carries source observations and time/context. Namespace aliases such as CNAME remain separate hostname entities.

### Multiplicity and conflict policy

| Situation | Representation and behavior |
| --- | --- |
| One hostname, multiple IPs in an answer | One hostname with an answer-set observation and multiple edges; normal multiplicity, not a conflict. |
| Multiple names, one IP | Separate hostname and web-origin entities share an IP; preserve Host/SNI context and never propagate app-specific results to every name. |
| Different answers across time | Historical observations and time-filtered edges; possible change, not automatic contradiction. |
| Different resolvers/vantages at similar times | Show divergent answer sets with resolver, time, TTL and CNAME chain. Offer a recheck; do not select a majority as universal truth. |
| Open vs closed, or competing service fingerprints | Compare endpoint, transport, timestamp, vantage and probe evidence. Preserve disagreement and show a review indicator where observations are comparable. |
| Different owner/provider labels | Keep registered holder, routing operator, cloud provider and analyst business attribution in separate fields. Competing claims in the same role can require review. |
| NXDOMAIN vs timeout | Separate negative DNS evidence from lack of an answer. |
| Evidence inherited from another collector | Preserve upstream provenance; two wrappers around the same source do not count as two independent confirmations. |

Retain raw observations immutably. Materialized views compute recent state per context, using a versioned field-specific policy. Never use a universal last-upload-wins rule or average scanner confidence scores. Service evidence rank, recency and context are displayed explicitly. Analyst preferences are reversible annotations with author/reason/time; they do not delete competing data.

Asset detail gains a Relationships tab, Evidence tab and Disagreements tab. Disagreements display competing claims side by side, source links, observation times, contexts and actions to annotate, mark expected, or request a recheck. Actual identity merges/splits require an explicit reversible analyst operation and audit record; ordinary DNS multiplicity needs neither.

Additional acceptance cases: multiple A/AAAA records, round-robin order changes (same answer set), CNAME chains, shared CDN IPs, distinct virtual hosts, divergent resolver results, historical IP changes, stale imported DNS, competing service probes, nested-provider duplication and uninterpreted raw records.

### Discovery references

- BBOT flags and internal modules: https://www.blacklanternsecurity.com/bbot/Stable/scanning/
- dnsx resolver/raw output and wildcard constraints: https://docs.projectdiscovery.io/opensource/dnsx/usage
- ARIN registry API: https://www.arin.net/resources/registry/whois/rws/api/
- RIPEstat announced prefixes: https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes
- RIPEstat multi-origin prefixes: https://stat-ui.stat.ripe.net/docs/data-api/api-endpoints/prefix-overview.html
- httpx output capabilities: https://docs.projectdiscovery.io/opensource/httpx/usage
- gowitness screenshots and artifacts: https://github.com/sensepost/gowitness
- Censys host/web/certificate records: https://docs.censys.com/docs/platform-quickstart-guide
- Katana structured output: https://docs.projectdiscovery.io/opensource/katana/running
- Nuclei template checks: https://docs.projectdiscovery.io/opensource/nuclei/overview
