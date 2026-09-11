# Vandal UAT handoff

## Current status — second pass deployed

The draft workflow release was deployed and verified on **2026-09-11 UTC** (September 10 in the user's local time). This replaces the earlier interrupted-work status.

- Original design: [uat-redesign.md](uat-redesign.md).
- Current workflow and limitations: [scan-drafts.md](scan-drafts.md).
- Local repository: `/home/gh0st/dev/vandal`.
- Remote application: `ubuntu@35.87.45.76`, `/home/ubuntu/dev/vandal`.
- Service: `vandal`; port: **8765**. Binding and authentication configuration were preserved.
- User preference: functional improvements first; aesthetic changes in the final pass.

## Live features

The first pass provides the current host projection, hostname-first browsing, grouped ports and host/CVE claims, retained source/address history, persistent Explore views, host popouts, selection, page sizes, and Load more.

The second pass adds:

1. Offline command drafts that preserve target identifiers and show warnings despite missing tools, invalid options, or absent DNS validation.
2. Editable draft text and notes, saved revisions, exports, and reopening from Saved drafts.
3. Separate profile-readiness validation; failures leave the draft editable and can be saved with it.
4. Preservation of edited draft text/notes when profile controls change; concurrent saves are rejected without discarding local edits.
5. Draft revisions in Timeline, clearly distinguished from executed commands, with revision numbers in CSV exports.
6. A host-level Sync DNS entry point into the existing two-resolver validator. Opening it does not launch queries or add scope; the operator reviews/runs the structured profile.
7. Per-tool Configure buttons and Saved drafts on Scans.

Free-text drafts remain review documents. Executable changes use the existing structured profile controls. The job builder, Nmap options, worker, and DNS probe implementations were not modified. Nmap execution still uses its existing DNS snapshot and scope checks. Separate full pages per tool and aesthetic changes remain later work.

## Validation and recovery

- **80 tests passed** on the remote staging copy using the remote Python environment.
- Playwright/Chromium checks passed for offline drafts, retained edits/errors, revisions/conflicts, exports, Timeline links, DNS entry, and mobile layout. Validation responses were mocked and job-launch requests blocked; no target scans were launched.
- The additive migration was rehearsed twice on a private copy of the live database. Hash comparisons verified that existing evidence, decisions, assets, imports, jobs, scope rules, web captures, and credentials were unchanged.
- Live authenticated checks passed for the current inventory, dashboard, host detail, domains, passive filtering, draft list, Timeline, and an offline draft proposal. The checks reported 1,160 hosts and 536 host/CVE groups.
- Deployed source hashes, database integrity, and unchanged credentials were verified.

Current release backup: `/home/ubuntu/vandal-drafts-release-20260911T002249Z`.

It contains the source backup, database backup, file manifest, deployment script, migration-check script, migration rehearsal copy, and `release.json` verification record. Source rollback can leave the additive draft tables in place; do not overwrite live data to roll back these UI/API changes.

Previous inventory release backup: `/home/ubuntu/vandal-uat-release-20260910T221946Z`.

Earlier read-only comparison backup: `/home/ubuntu/vandal-uat-backup-20260910T213816Z`.

## Relevant source and tests

- `vandal/drafts.py`, `vandal/migrations/007_scan_drafts.sql`.
- `vandal/static/scan-drafts.js`, `vandal/static/scan-composer.js`.
- Integrations: `vandal/app.py`, `vandal/static/app.js`, `vandal/static/host-workspace.js`, `vandal/templates/index.html`.
- `tests/test_drafts.py`: eleven draft acceptance tests.
- `tests/browser_drafts.py`, `tests/browser_fixture.py`: optional browser checks with temporary fixture data.

The repository remains untracked in Git; preserve the existing files. Deployment scripts and source hash baselines are release-specific. Do not reuse an old deployment script unchanged.
