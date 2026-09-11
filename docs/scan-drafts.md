# Scan drafts and DNS validation

## Draft workflow

1. Open **New scan**, choose a profile, and enter targets/options. **Scans → Configure** opens a specific profile.
2. **Generate draft** works without querying DNS or requiring the scanner to be installed. Entered target identifiers stay in the draft target list. Invalid options, missing tools, and scope issues appear as warnings.
3. Edit the draft command and notes, then **Save draft**. Further saves create revisions. **Saved drafts** is available in the composer and Scans. Draft JSON exports include identifiers, configuration, text, notes, and warnings.
4. **Validate profile** checks the existing execution requirements. A failure leaves the draft editable and can be saved with it. Successful validation shows the executable profile command and any address snapshot or exclusions.

Free-text commands are review documents. To change an executable profile, use its controls. Editing draft text disables Run until it is reset to the generated profile command. The job API rejects draft text and draft IDs as execution inputs.

Changes to profile controls preserve edited draft text and notes while invalidating the readiness check. When another session saves the same draft, a stale save is rejected without discarding local edits. Reopen the draft to inspect the intervening revisions.

Timeline labels every saved revision **DRAFT**, separate from executed scan jobs and imported artifacts. Timeline command displays/exports redact common credential arguments. Authenticated draft detail/export retains the original review text. Excluded target drafts, including their revisions, are hidden until the exclusion is removed.

## DNS validation

On a hostname's host panel, **Sync DNS** opens the existing DNS validation profile with that hostname as its target. Generate the draft and validate it, then review/run the structured profile. The existing validator queries A, AAAA, and CNAME records through its two configured public resolvers and retains each response separately.

Once the job's output is ingested, the current host projection uses the new address evidence. **Refresh host** reloads an open panel; Explore's new-evidence indicator reloads the list. Original address evidence remains in History. Opening Sync DNS does not launch a lookup or add scope automatically.

Nmap execution still uses the existing DNS snapshot and scope checks. This release separates draft preparation from those checks; it does not remove execution checks or add arbitrary shell execution. Separate full pages per tool and aesthetic changes remain later work.

## Validation and migration

- `tests/test_drafts.py`: fixture tests for offline proposals, saved revisions, invalid input, authorization, exclusions, exports, Timeline, and imported DNS evidence.
- `tests/browser_drafts.py`: optional Playwright/Chromium check using a temporary localhost fixture, mocked validation responses, and blocked job-launch requests.
- `007_scan_drafts.sql`: additive draft/revision tables; existing evidence, decisions, users, and job records are not rewritten. Source rollback can leave these additive tables in place.
