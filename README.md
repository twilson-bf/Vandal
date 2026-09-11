# vandal

External assessment workspace, named for Vandal Blast. A local Python server joins
scan evidence into a reusable inventory with an orange, LotusPetal-inspired interface.

## Start the workspace

```bash
python3 run.py
```

Open **http://127.0.0.1:8765**. Sign in as `admin`; first startup saves a generated
password to `data/initial-admin-password` (readable only by your user). Alternatively,
set `VANDAL_ADMIN_PASSWORD` before the first startup. The server starts one supervised
worker for uploads and scan jobs. Opening the app does not start a scan.

For Windows access when running inside WSL, start with `python3 run.py --wsl`.
This listens on all IPv4 interfaces and permits the current WSL IP addresses through
the host filter. Use the Windows access URL printed at startup if localhost forwarding
does not work. Restart this command if WSL's IP changes. Keep this mode on a trusted
network; the default launch remains loopback-only.

If BBOT reports missing system dependencies, run `./install.sh --system` in your
terminal, then preview the scan again. BBOT 3.0.2 checks core packages even with
module dependency installation disabled; Vandal checks these before launch so
the job does not wait for a sudo password.

The current version includes:

- Engagement-separated inventory, hostname/IP relationships, port/service evidence,
  notes, tags, saved filters, domain tree, geographic map and source drawers.
- Uploads and folder imports for Nmap XML/text, Nessus XML and the supplied summary
  HTML layout, BBOT JSON/JSONL, DNS/HTTP JSONL, discovered-ports CSV/JSON and seed lists.
- Recovery of fully closed Nmap hosts from incomplete XML, explicit partial/failed
  imports, duplicate-file detection, and reversible import archival.
- Full source artifacts and searchable normalized/raw records, including informational
  plugins and unmapped JSON. Nessus summaries cannot supply missing plugin output.
- Broad items of interest with evidence links; vulnerability confirmation is a manual
  analyst decision. Nothing is automatically promoted to a confirmed vulnerability.
- Logged BBOT passive discovery with DNS resolution, independent DNS validation, Nmap service scans and
  ProjectDiscovery httpx jobs. Scope includes/excludes, command previews, cancellation,
  stdout/stderr downloads, automatic result ingestion and CSV/JSON timeline exports.
- Authentication, admin/operator/viewer roles, engagement memberships and mutation audit.

Overview is the home page: inventory, coverage, active/recent scans, imports and
new review items. **New scan** remains in the global header. It accepts pasted
targets and optionally adds them to scope, showing additions in the command preview.

Explore defaults to hostname-first results, with IP-only rows where no associated
hostname is known. IP-first and hostnames-only modes remain available, independently sorted by
address, hostname, latest observation or vulnerability count. Domains provides a
dedicated hostname inventory. Host links open a wide pane over the existing page,
preserving its query and scroll position. General information, vulnerabilities and
service output appear together. Evidence opens above the host pane; closing it returns
to the host. Direct `#host?id=...` URLs remain available. Sources and original
records remain available from every service observation.

Search supports ANDed terms, quoted values, and `-` negation. Examples:

```text
hostname:kohler.co.in port:443
product:nginx country:"United States"
has:vuln source:shodan
scanned:false scope:included
has:ports -port:443
```

Supported fields: `hostname`, `ip`, `net`, `port`, `product`, `service`, `country`
(country name), `org`, `asn`, `source`, `has` (`ports`/`vuln`), `scanned` (`true`/`false`),
`scope` (`included`/`excluded`/`unassigned`), `coverage` (`scanned`/`passive`/`unscanned`),
and `cve`. Plain text searches identities, tags, provider and retained service output.
Unsupported filters show an error without removing the search controls. This is a
documented subset, not full Shodan query compatibility. Facets count matching assets.

One service summary represents an owner/protocol/port. It prefers the latest
non-passive observation when available and retains all history. IPs do not inherit
ports or vulnerability claims from neighboring hostnames. Hostname pages can display
related IP endpoints with explicit owners. Unresolved hostnames remain in Domains.
Coverage means evidence exists in retained scans, not that every port was checked.

The BBOT profile includes `shodan_idb` (Shodan InternetDB, no API key) for passive
port and technology observations. These ports are labeled `passive`; provider CVE
claims create unconfirmed `potential CVE` findings with linked scan records, deduplicated
by host and CVE. Existing records are backfilled on startup; subsequent evidence does
not overwrite analyst notes or status. InternetDB lookup time is not
the provider's original scan time. Secondary DNS validation remains a separate job.

Click an Explore port badge for its source records, observed states, services and
timestamps. Use `has:ports` or `-has:ports` to select open-port coverage.

Service filters search **historical observations**, explicitly labeled in the UI. A
missing result does not establish closure or remediation. `tcpwrapped` is retained as
a probe response, not a confirmed service. Domain/country/ASN filters also match directly
related assets; relationships retain their source record rather than merging identities.

The timeline records a queued job before execution, then start/end UTC timestamps,
operator, tool version, exact argument vector, target snapshot, exclusions and exit
status. Imported commands are labeled separately, with original scan times when parsed;
upload time is retained independently. Common credential arguments are redacted in
imported-command timeline displays/exports. Original artifacts and raw tool output remain
access-controlled evidence and can still contain sensitive content.

## Import existing data

```bash
.venv/bin/python -m vandal import /path/to/scans --engagement 'Client / External 2026'
```

This recursively imports supported files and creates the named engagement if needed.
Reruns skip identical content. The UI's Imports screen can archive, restore or retry a
failed/interrupted import. Archived observations disappear from the active inventory,
but their artifacts and analyst annotations remain intact.

## Scan execution

Add explicit include/exclude rules under **Scope**, select assets in **Explore**, then
choose **New scan**. Preview and run the command. No freeform shell execution is exposed.
Nmap accepts IPs and hostnames. Hostname previews show all resolved addresses for the
selected family (IPv4 by default). Excluded addresses block the target. DNS mappings
are checked again when queuing and dispatching; changes require a new preview. Nmap
receives the checked IP list, and hostname mappings are retained as scan evidence.
The passive BBOT profile offers `crt`, `hackertarget`, `rapiddns`, and `shodan_idb`;
DNS resolution is enabled and automatic dependency installation is disabled.
Unavailable upstream sources are visible in tool output; no account keys are required.

The scan composer provides light, detailed-service, and vulnerability-review Nmap
presets. Tune custom/top/all TCP ports, version intensity, host discovery, IPv4/IPv6,
timing, rate, retries, and host/script timeouts. Optional NSE bundles cover service
metadata, TLS ciphers, and scripts tagged both `safe` and `vuln`, excluding external,
intrusive, DoS, exploit, brute-force, broadcast and fuzzing categories. Vulners is a
separate opt-in external software/CPE lookup, with a minimum CVSS control. These
category labels describe Nmap's classification, not proof that a check is harmless.
Positive NSE CVE claims become unconfirmed review items with original script evidence.
See https://nmap.org/nsedoc/scripts/vulners.html for the external lookup behavior.
HTTP inventory has separate rate, concurrency and request-timeout controls.

Jobs run serially with a one-hour timeout and a 20 MiB combined log ceiling. Cancellation
terminates the process group; valid partial output can still be ingested. Interrupted
running jobs are not replayed after restart. HTTP jobs recheck current DNS against IP
exclusions before dispatch; they do not follow redirects. This is a dispatch-time check,
not a network-level egress boundary against DNS changes during a long-running scan.

Nessus execution, screenshot capture/gallery, company/BGP enrichment, arbitrary CSV
column mapping, scheduled scans, analyst service-verification controls and a full
historical diff engine remain follow-on integrations. Their installed dependencies do
not imply that those job profiles are enabled. The current DNS validator uses dnspython
to retain a separate observation per resolver and query type; dnsx is installed for a
future dedicated profile. Unknown JSON records remain available without a custom parser.

## Configuration and data

Local Lotus typefaces are imported from the sibling `~/dev/lotus-fonts` checkout
when available. Run `python3 scripts/import-fonts.py` to refresh them, or pass another
font directory as its argument. The installer also performs this idempotent copy.
`VANDAL_FONTS_DIR` overrides the default source. Licensed font binaries stay in the
Git-ignored `vandal/static/fonts/local/` directory; the bundled open fonts remain
fallbacks when local fonts are absent.

| Variable | Purpose |
| --- | --- |
| `VANDAL_DATA` | Database, artifacts and job logs; defaults to `./data` |
| `VANDAL_HOST`, `VANDAL_PORT` | Default `127.0.0.1:8765` |
| `VANDAL_ALLOWED_HOSTS` | Comma-separated hostnames for access through another hostname |
| `VANDAL_COOKIE_SECURE=1` | Secure cookies when served behind HTTPS |
| `VANDAL_WORKER=0` | Disable the automatic worker (tests or an independently managed worker) |
| `VANDAL_GEOIP_CITY`, `VANDAL_GEOIP_ASN` | Local MaxMind-compatible databases |

The **Scope + Nmap** action on IP rows and IP details adds that exact IP to scope,
then queues a logged service scan using Vandal's defaults (22,80,443,445,3389,8080,8443)
plus observed TCP ports on the IP and its associated hostnames. Exclusions take
precedence. Repeated clicks reuse an active Nmap job for that IP.

These jobs automatically geolocate the selected public IP using the configured local
city database, or HTTPS `ipwho.is` when no city database is configured. The fallback
sends the selected IP to that provider; the response or error is retained in the job.
Geolocation failures do not prevent Nmap from running. Private IPs are skipped.
A separate background enrichment worker also queues every active-import IP missing
coordinates, including hosts added by later uploads. It skips non-public addresses,
caches results per IP, processes requests at a low rate, and backs off on failures
or provider rate limits. Overview shows progress. Work resumes after restart.
After configuring databases, run `.venv/bin/python -m vandal geo`
to enrich existing IP records. Map coordinates describe IP infrastructure; hostnames
without their own coordinates are still available through related IP evidence.

Create another account using `.venv/bin/python -m vandal user NAME --role operator
--engagement ID` (password is entered interactively). A viewer cannot mutate content.
Membership management currently uses the CLI; admin accounts can access all engagements.

Storage uses SQLite WAL with numbered transactional SQL migrations in
`vandal/migrations`. Original artifacts are content-addressed and stored outside the
static directory. Back up the entire data directory with the server stopped, including
the database, artifacts and job logs. Do not copy client data into Git.

## Install

Supported: Linux x86_64/arm64, Python 3.11–3.13. Debian, Ubuntu and Kali have automated
system-package setup. Other Linux distributions need Nmap, Chromium, CA certificates
and Python venv support installed through their own package manager.

```bash
./install.sh --system
./install.sh doctor
```

`--system` uses sudo only to install missing distribution packages. It can prompt for
your password. Do not run the whole installer with sudo: Python environments and tools
belong to your user.

System setup temporarily selects your configured official distribution repositories,
preserving suites (including `kali-last-snapshot`), components and signing keys. Both
APT update and installation use isolated package indexes, so a broken unrelated source
such as HashiCorp cannot block setup. Your `/etc/apt` files are not modified and normal
signature verification remains enabled. Unrecognized custom mirrors require manual
system package installation.

On systems where the prerequisites already exist:

```bash
./install.sh
```

Use `VANDAL_PYTHON=/path/to/python3.12 ./install.sh` to select Python. If venv creation
is unavailable, install the matching interpreter's venv package first. Chromium can
be supplied through `VANDAL_CHROME=/path/to/chrome`; on Ubuntu, the distribution's
Chromium package may require snap support.

## Included dependencies

| Component | Installation |
| --- | --- |
| Future application, parsers, DNS/HTTP/GeoIP libraries | `.venv`, hash-checked transitive Python lock |
| BBOT | Isolated `.tools/bbot`, separate hash-checked Python lock |
| dnsx, ProjectDiscovery httpx, gowitness | Pinned official release binaries in `.tools/bin` |
| Nmap, Chromium | Distribution packages, with installed versions shown by doctor |
| Katana, Nuclei, TLSx | Optional pinned binaries: `./install.sh --extras` |
| Nessus | Separately installed/licensed vendor product; not needed to import its reports |

Python's `httpx` library and ProjectDiscovery's `httpx` executable are different
dependencies. Always use `.tools/bin/httpx` for the scanner. BBOT is available through
`.tools/bin/bbot`. The future server will use explicit executable paths, not assume a
particular shell PATH. No global Python packages, Go compiler, Node build, account API
keys, or shell profile edits are required.

BBOT itself is installed; module-specific dependencies and passive profile validation
will be handled when we build the discovery profiles. Installation does not run BBOT's
automatic module provisioning or a scan. Likewise, Nuclei templates are not downloaded
or enabled here; approved template packs will be pinned separately. GeoIP database
files are not bundled; the library is installed and bulk local geolocation requires a
database is supplied. Registry/RDAP/BGP integrations need no additional executable.

## Idempotence and integrity

Repeat the same command to repair or complete an interrupted setup. The installer:

- takes an exclusive installation lock;
- verifies cached downloads against committed SHA-256 digests;
- extracts only the requested executable and atomically replaces it;
- skips unchanged binaries after checking their installed hashes;
- checks Python lock hashes, installed inventories and `pip check` before skipping;
- installs only missing OS packages, without upgrading existing ones;
- preserves existing application data and never starts a server or target scan.

System packages track the distribution rather than a pinned cross-distribution version.
Python and downloaded executable versions are pinned in `dependencies/`. Both binary
architectures have manifest entries; installation has only been exercised on the local
architecture. Python source distributions may need platform build prerequisites if
wheels are unavailable.

`doctor` exits nonzero if a baseline dependency is missing or fails its version check.
Nessus is optional. It checks installation, not scan readiness or browser rendering.

```bash
./install.sh doctor --json
./install.sh doctor --extras
./install.sh --offline
```

Offline reruns work when the environments and verified binaries already exist. Offline
repairs can reuse `.cache/downloads`; Python repairs need a separately prepared
`.cache/wheels` wheelhouse. The installer never silently falls back to the network in
offline mode. `doctor` does not invoke install/update commands; upstream version commands
may still initialize their own caches.

## Development checks

```bash
.venv/bin/python -m unittest discover -s tests -v
bash -n install.sh scripts/install-system.sh
```

Tests use temporary files and mocked network/process calls. They do not run target scans
or require the tool dependencies to be installed.

Design: [docs/design.md](docs/design.md). Lock maintenance:
[dependencies/README.md](dependencies/README.md).

## CVE metadata enrichment

Potential CVE IDs are looked up through the public CVE Program API, without an API
key. Only CVE identifiers are sent. Descriptions, published/modified dates, CVSS
scores with sources, affected products and references are cached with the original
CVE record and refreshed daily. The host pane and finding editor show these details,
including queued/failed states. Enrichment never changes analyst confirmation.

Background location and CVE work runs independently of the scan loop in the supervised
worker. `VANDAL_WORKER=0` disables both scans and background enrichment for tests.

Overview's IP location panel uses the local LotusPetal globe.gl renderer with blue
land and grid lines and orange markers. Drag to rotate; scrolling over the globe
zooms without scrolling the page. Buttons provide zoom, reset, expansion and a flat-map
fallback. Nearby hosts cluster by screen distance when zoomed out and separate as
you zoom in. Each marker opens its host or grouped host list. Cluster lists show
associated hostnames beside IPs, sorted by hostname with unnamed IPs last.
Selecting a host opens its existing details pane. Background geolocation updates the
markers without resetting the camera; unlocated hosts remain counted as unknown.
The renderer and country geometry are served locally, without external map tiles.

Scope accepts pasted newline/comma-separated targets and UTF-8 text files (including
headerless CSV lists), with IPv4/IPv6 addresses, CIDRs, hostnames, and inclusive
`start-IP - end-IP` ranges. Preview shows normalized rules and the matching asset
count; repeated submissions do not duplicate rules. Domain rules cover subdomains.
Exclusions apply to project read APIs, inventory, maps, findings, relationships,
records, import summaries and scan history. Mixed raw records and original files
containing excluded assets are hidden rather than partially rewriting evidence.
Original data remains intact; remove exclusions in Scope to restore visibility.
Queued scans recheck scope before dispatch. Adding exclusions cancels matching
queued jobs and requests cancellation of matching running jobs.

For Windows LAN access, start Vandal with the Windows LAN address allowed:
`python run.py --wsl --allow-host 192.168.1.77`.
Run `scripts/enable-lan.ps1 -WslAddress 192.168.219.127 -LanAddress 192.168.1.77`
in Administrator PowerShell. The script updates TCP 8765 forwarding and allows only
local-subnet clients through Windows Firewall. Rerun with current addresses if
Windows DHCP or a WSL restart changes them. The normal Vandal login still applies.

## Web inventory and gowitness

Explore → **Web capture** opens the scan composer with checked assets, or every
matching inventory result across all pages if nothing is checked. With no filters,
this uses the full visible inventory. The target list is editable. The normal
scope preview and optional “Add entered targets to scope” apply before execution.

The **Web inventory & screenshots** profile snapshots each host's observed open TCP
ports, including associated IP service observations for hostnames. Ports 80/443 can
be included even without prior observations. HTTP and HTTPS are validated on each
candidate port without following redirects; responding URLs go to gowitness.
Choose validation/capture timeouts, concurrency, render delay, and full-page capture.

A job-local proxy restricts validation, redirects and browser resources to candidate
hosts/ports and checks current exclusions on every connection. Off-target resources
may therefore be absent from screenshots. Gowitness and Chromium come from the
existing dependency installer; no additional account or standalone report server
is required. No scan is started by opening a form or preview.

**Explore → Web** provides screenshot cards, titles, status codes, technologies,
failures, host links, capture history, job filtering, and a searchable report. Click a
card for the screenshot and complete gowitness/HTTP metadata, or export the filtered
report as JSONL. Screenshots and reports require the normal project login and honor
exclusions. Captured HTML is displayed as escaped data, never served as an active page.

Each stage's command, status, timing and exit code are in the scan job, alongside
stdout/stderr and ingested HTTP evidence. Original `gowitness.jsonl`,
`gowitness.sqlite3`, validation results and screenshots live under `data/jobs/<id>/`.
Jobs retain the existing one-hour runtime limit. Interruptions retain completed
captures and validation records; incomplete browser captures appear as failures.
