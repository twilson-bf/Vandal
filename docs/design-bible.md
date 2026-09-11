# Vandal fantasy-tech interface design bible

Status: **canonical**  
Audience: product designers, frontend developers, coding agents, visual-review agents, and anyone extending Vandal  
Applies to: the application shell, Overview, Explore, host dossiers, scan control, imports, evidence, maps, drawers, responsive layouts, and future scan-specific screens  
Approved reference implementation: `design/fantasy-tech-accents` at `0d36904`

This document is written as an implementation contract. When an agent changes Vandal's interface, it should use these rules before applying its own design defaults. If another design note conflicts with this document, follow this document unless the user explicitly requests a new direction.

## 1. The intended experience

Vandal is a work tool for an external red-team assessment. It should feel like a piece of specialized technical equipment from a believable fictional world: terse, dense, slightly severe, and exciting to operate. It should support the fantasy that the operator has opened a privileged interface over a large body of live reconnaissance evidence.

The interface is not a corporate security portal, a SaaS analytics product, a sales dashboard, or a movie prop. It must remain fast and legible during real assessment work. Its fiction comes from combining useful data with a strong visual apparatus.

The desired first impression is:

> I have access to a powerful, peculiar system built for this exact work.

The desired sustained-use impression is:

> I can read, compare, search, and act on this data for hours without fighting the interface.

Both impressions matter. An interface that is usable but visually anonymous fails. An interface that looks exciting but obscures evidence also fails.

## 2. The central visual model

Every Vandal screen combines two layers.

### 2.1 The work surface

The work surface contains hostnames, addresses, services, vulnerabilities, scope rules, scan options, commands, timestamps, filters, and evidence. It is compact, stable, and comparatively quiet.

Work surfaces use:

- Near-black and charcoal planes.
- Clear columns and predictable alignment.
- Fraktion Mono for nearly all operational text.
- Small radii or square corners.
- Background-value changes and spacing instead of hairline separators.
- Persistent context during exploration.
- High information density without tiny unreadable text.

### 2.2 The apparatus

The apparatus is the decorative fiction surrounding and puncturing the work surface. It makes Vandal feel manufactured rather than themed.

The apparatus uses:

- Broad orange or green signal bands.
- Deep-black terminal apertures.
- Raw scanner output and command fragments.
- Oversized record numbers and system labels.
- Cropped or interrupted typography.
- Striped, dithered, or printed surface texture.
- Stepped corners and solid geometric blocks.
- Labels that imply channels, registers, buffers, and evidence buses.
- Deliberate visual overflow at the edges of a plane.

The apparatus may be decorative, but it cannot lie about operational state. `RAW EVIDENCE BUS` is a label for a real evidence subsystem. `ACCESS GRANTED TO MAINFRAME 7` would invent a state and should not appear.

### 2.3 The target ratio

Aim for roughly **85% work surface and 15% apparatus** within a typical viewport.

This is a perceptual ratio, not a DOM measurement. The apparatus should occupy enough area and contrast to establish a world. It should not surround every row, control, or panel.

If a screen feels like an ordinary dark dashboard, increase the apparatus through one or two large gestures. Do not scatter more tiny accents everywhere.

If a screen feels like a game menu, remove repeated texture and decoration from the data plane. Keep one strong header, one raw aperture, and the semantic state colors.

## 3. Design principles

### 3.1 Decoration is structural

Decoration should define regions, materials, and modes. A wide striped block can identify a scanner module. A pale identity plate can distinguish canonical host facts from accumulated evidence. A black-green aperture can expose raw output.

Avoid decoration that merely sits beside content:

- Random warning triangles.
- Tiny cyberpunk glyphs.
- Decorative hex strings.
- Meaningless grid overlays.
- Glowing dots with no state.
- Repeated corner brackets on every card.

Prefer a few large decorative moves over many small ones.

### 3.2 Raw data creates credibility

Whenever the backend already retains raw command, banner, script, resolver, or event output, expose a useful excerpt in an expandable terminal aperture.

Raw apertures must use actual retained data. They may add presentation labels such as `RAW SERVICE OUTPUT // RECORD 32306`, but they must not fabricate output.

The surrounding normalized view explains the evidence. The aperture proves where it came from.

### 3.3 The fiction has a manufacturing culture

Vandal should use a consistent vocabulary and set of graphic forms, as if one organization designed the entire system.

Preferred nouns:

- `SURFACE INDEX`
- `PROCESS CONTROL`
- `HOST`
- `IDENTITY`
- `CURRENT EVIDENCE`
- `RAW SERVICE OUTPUT`
- `TARGET BUFFER`
- `PROFILE`
- `COMMAND`
- `RESOLVER`
- `PROJECTION`
- `RECORD`
- `CHANNEL`
- `HISTORY`
- `REVIEW`

Preferred delimiters:

- `//` between a region and its qualifier.
- `/` inside compact paths or modes.
- `::` inside terminal-style status statements.
- `#` before database or job identifiers.
- `=` in raw key/value readouts.

Use this vocabulary consistently. Do not invent a different sci-fi dialect for each page.

### 3.4 Utility copy remains plain

Atmospheric labels can be terse. Instructions, warnings, errors, and buttons must remain direct.

Good:

- `Sync DNS`
- `Run validated profile`
- `DNS changed after queuing; preview a new scan.`
- `RAW SERVICE OUTPUT // RECORD 32306`

Bad:

- `Initiate cyber reconnaissance sequence`
- `Unleash scan`
- `Engage target matrix`
- `The system hungers for more evidence`

Vandal is allowed to look fictional. It should not speak like marketing copy or role-play prose.

### 3.5 State colors keep fixed meanings

Decoration never overrides semantic color. A confirmed vulnerability stays red even inside an orange page. Geographic elements stay blue. Raw terminal output stays green.

The operator should learn the palette once and trust it everywhere.

### 3.6 Quiet data, loud framing

Data rows should remain calm enough to scan rapidly. Put stronger contrast into headers, signal bands, identity plates, and terminal apertures.

Do not place diagonal stripes, glow, oversized labels, or bright color behind every hostname or table cell.

## 4. Reference character

The principal visual reference is the Marathon Codex image supplied by the user. Relevant characteristics include:

- A central readable document embedded in a larger system.
- Broad, repeating status bands.
- A mixture of black terminal material and pale inverse plates.
- Large areas of texture and corrupted imagery.
- Cropped interface elements that imply a world beyond the viewport.
- Strong use of one signal color rather than rainbow accents.
- Dense monospaced copy balanced with large graphic gestures.

Original Marathon terminals contribute connection metadata, strong document framing, and terse controls. Contemporary Marathon interface studies contribute authored typography, block geometry, and materials derived from the fictional world. Alien: Isolation contributes the discipline of designing each screen as a specific machine instead of applying a generic sci-fi skin.

Useful references:

- Marathon story terminals: <https://marathon.bungie.org/story/arrival.html>
- Michael Rigley's Marathon interface work: <https://www.behance.net/gallery/205038723/MARATHON>
- Jon McKellan on Alien: Isolation: <https://www.artofthetitle.com/title/alien-isolation/>

Use references to understand composition and material. Do not reproduce protected artwork, logos, fictional company names, or exact screen layouts.

## 5. Visual vocabulary

### 5.1 Shell

The shell contains global navigation, engagement context, the persistent scan action, operator state, and broad system decoration.

Current shell characteristics:

- Approximately 50px top bar.
- Narrow left rail.
- An 18px orange system tape below the top bar.
- Dark block-pattern substrate visible in margins.
- Compact UTC clock.
- Orange `V/` mark paired with the lowercase Vandal wordmark.

The shell may be more atmospheric than the work surface. Texture must remain low contrast and fixed. It must not jitter or animate under the page.

### 5.2 Signal band

A signal band is a broad, shallow region that declares the current subsystem. It usually combines a solid label block with a patterned continuation.

Examples:

- `SURFACE INDEX` above Explore.
- `PROCESS CONTROL` above Scans.
- The global external-surface tape.

Rules:

- Use at most one prominent local signal band near the top of a screen.
- Give it a subsystem label, not a slogan.
- It can use orange for operator/action systems or green for evidence/index systems.
- Keep it between roughly 24px and 76px tall depending on importance.
- Use solid blocks and repeating patterns, not a thin outline.
- Clip or step one corner when useful.

### 5.3 Terminal aperture

A terminal aperture is a deep-black region exposing commands, output, resolver answers, service banners, or machine-readable state.

Rules:

- Use green as the default output color.
- Use orange for prompts, editable arguments, or warnings within the aperture.
- Use red only for real failures or confirmed vulnerabilities.
- Always escape untrusted content before inserting it into HTML.
- Preserve whitespace where it communicates structure.
- Wrap long unstructured output rather than forcing horizontal page overflow.
- Provide expansion or scrolling for long output.
- Label its provenance with record, job, or import identity when available.
- Do not type out content with animation.
- Do not add fake cursor blinking to static evidence.

The terminal aperture should visually contrast with normalized controls. It is an opening into the retained source material.

### 5.4 Identity plate

An identity plate presents the canonical subject currently being inspected.

The approved host treatment uses:

- A pale warm-gray field.
- Dark text.
- A large hostname.
- A high-contrast oversized host serial on a striped dark block.
- Compact badges for coverage, open services, primary address, and DNS state.
- A small black-green identity aperture.

Identity plates are rare. Use them for the primary subject of a detailed view, not every result row.

### 5.5 Register

A register is a dense normalized list: hosts, services, vulnerabilities, jobs, imports, or scope rules.

Rules:

- Align repeated fields.
- Use alternate surface values only when they improve tracking.
- Keep semantic counts explicit: `hosts`, `addresses`, `open services`, `host/CVE pairs`.
- Use one stable row identity.
- Use oversized low-contrast record numbers only as background decoration.
- Ensure decorative numbers cannot be mistaken for operational values.
- Keep row hover and selected states unmistakable.

### 5.6 Module

A module represents a tool or operating mode such as Nmap, BBOT, DNS validation, httpx, or GoWitness.

Modules may use:

- A large two-digit index.
- A striped corner or lower block.
- A tool-state label.
- A concise capability description.

Modules should not become rounded product cards. They are components of one control system.

### 5.7 Inverse plate

An inverse plate uses pale warm gray with dark text. It provides sharp material contrast against the black shell.

Use it for:

- Active navigation.
- A primary inspected identity.
- Rare document-like or selected states.

Do not use a pale plate for every metric or panel. Its rarity gives it force.

## 6. Color system

The current prototype establishes these base values:

```css
--bg: #0b0c0e;
--deep: #070809;
--surface: #19191e;
--surface-hi: #232329;
--surface-soft: #2b2b31;
--ink: #f0eee8;
--muted: #929198;
--orange: #ff8a24;
--amber: #efaa52;
--phosphor: #61d36c;
--blue: #69aef5;
--red: #ff5365;
--warm-paper: #d5d2c9;
--void: #050706;
```

### 6.1 Orange: operator agency

Orange identifies actions, editable prompts, current operating mode, and selected pathways.

Use orange for:

- Primary actions.
- The global system tape.
- Process-control title blocks.
- Links into evidence when a neutral link would disappear.
- Active location markers without confirmed vulnerabilities.
- Warnings when amber is too weak against a dark surface.

Do not use orange merely because an element is first in a list.

### 6.2 Green: raw machine output

Green belongs to terminal apertures, verified successful state, and live evidence channels.

Use green for:

- Raw Nmap, BBOT, DNS, HTTP, and service output.
- Completed/healthy state.
- Open-service state.
- Evidence-index signal bands.
- Machine-readable key/value labels.

Green is not the global brand color. Large portions of normalized data should remain neutral.

### 6.3 Blue: geographic and network projection

Use blue for:

- The globe.
- Geographic projection labels.
- Network-coordinate context.
- Non-error informational process states when green would imply completion.

### 6.4 Red: analyst-confirmed risk

Use red for:

- Confirmed vulnerabilities.
- Confirmed-vulnerability map clusters.
- Blocking errors and failed processes.

Potential CVEs remain neutral, amber, or muted. Scanner claims must never receive confirmed red automatically.

### 6.5 Amber: uncertainty

Use amber for:

- Unvalidated DNS.
- Partial evidence.
- Passive-only state.
- Non-blocking warnings.

### 6.6 Warm paper: canonical focus

Use warm paper for selected navigation and host identity plates. Pure white looks sterile; blue-gray silver looks like a generic enterprise dashboard.

## 7. Typography

### 7.1 Families

- `PP Fraktion Mono` is the primary working typeface.
- `Shapiro 65` is the restricted display face for major titles, large subsystem marks, and oversized identifiers.
- Bundled open fonts remain fallbacks when private Lotus fonts are unavailable.

Do not silently substitute a proportional corporate sans-serif as the primary face.

### 7.2 Roles

Use these approximate roles:

| Role | Size | Treatment |
| --- | ---: | --- |
| Page title | 22–28px | Display face, uppercase, once per screen |
| Apparatus block | 18–34px | Display face, heavy, allowed to crop |
| Primary host identity | 18–26px | Mono, normal case, high contrast |
| Section title | 12–16px | Mono, medium weight |
| Data row | 11–13px | Mono, normal weight |
| Metadata | 9–11px | Mono, muted but readable |
| Machine label | 7–10px | Mono, uppercase, modest tracking |
| Raw output | 9–12px | Mono, generous line height |

### 7.3 Cropping and scale

Oversized decorative typography may crop against its container. Operational text may not.

Never truncate the only visible hostname, IP address, CVE, command, or failure reason without an accessible expansion path.

### 7.4 Case

Uppercase belongs to apparatus labels and compact metadata. Hostnames, commands, evidence, descriptions, and instructions use their natural case.

Do not uppercase whole paragraphs.

## 8. Shape, spacing, and materials

### 8.1 Geometry

Preferred geometry:

- Square or 1–3px corners.
- One stepped or clipped corner on a signal object.
- Broad blocks.
- Deliberately interrupted planes.
- Strong alignment.

Avoid:

- Large rounded cards.
- Pill-shaped containers for ordinary data.
- Thin neon outlines.
- Colored left-edge highlights.
- Hairline dividers between every row.
- Glassmorphism.

### 8.2 Separation

Separate regions through:

1. Spacing.
2. Background value.
3. A broad header plane.
4. Material contrast.
5. A signal band when the subsystem changes.

Do not default to a 1px border.

### 8.3 Pattern

Approved patterns include:

- Low-contrast diagonal industrial stripes.
- Coarse block fields.
- Sparse dithering.
- Repeating printed bars.
- Subtle phosphor line structure inside raw-output wells.

Patterns should be static. They should sit behind labels or in otherwise unused shell space. Never place a high-contrast pattern behind a table body or long paragraph.

### 8.4 Glow

Glow is allowed only as a restrained property of emitted-light elements:

- Map markers.
- Phosphor output.
- A current focus cursor.

Do not glow panel borders, buttons, headings, or every colored object.

### 8.5 Shadows

Use black offset shadows to suggest stacked physical planes. Avoid soft floating-card shadows associated with modern SaaS interfaces.

## 9. Information architecture and page application

### 9.1 Global shell

The shell must always expose:

- Vandal identity.
- Current engagement.
- Overview.
- Explore.
- Scans.
- Scope.
- Evidence destinations.
- Import scans.
- New scan.
- Operator/logout control.

The global system tape can carry subsystem nouns. It must not become a scrolling marquee or animation.

The top bar should remain compact enough that the data begins near the top of a laptop viewport.

### 9.2 Overview

Purpose: orient the operator, expose coverage, display geographic distribution, and surface recent changes.

Required composition:

- One subsystem aperture or signal block near the top.
- Compact numerical register.
- Blue globe as the central instrument.
- Coverage register beside or near the globe.
- Recent scans, hosts, services, imports, and review items below.

Decorative opportunities:

- `SURFACE` title block.
- Green normalized state readout.
- Oversized `GEO/PROJECTION` label.
- Striped blocks in section headers.
- Large low-contrast system typography in empty shell space.

Do not:

- Turn metrics back into large marketing cards.
- Add explanatory hero copy.
- let decoration compete with the globe.
- Repeat the same diagonal stripe in every table row.

### 9.3 Explore

Purpose: search and compare the current inventory without losing context.

Required composition:

- Local modes: Hosts, Domains, Web, Vulnerabilities.
- `SURFACE INDEX` signal band.
- Black query aperture.
- Filters/facets.
- Dense host ledger.
- Persistent selection and pagination controls.

The query aperture should look like a command channel while remaining a standard accessible form. `QUERY://` is a label; the input must still have an accessible name and ordinary editing behavior.

Host rows remain neutral. Oversized internal IDs may sit behind them at very low contrast. The primary hostname, current address, open services, risk, and last evidence must remain immediately readable.

Do not decorate individual rows with colored outlines or different random patterns.

### 9.4 Host dossier

Purpose: show the canonical current host, vulnerability decisions, service state, and source evidence without leaving Explore.

Required composition:

- Warm-paper identity plate.
- Large host serial.
- Canonical hostname and current address state.
- Confirmed vulnerabilities immediately visible in the top corner panel.
- Current identity and vulnerability register.
- Current services with expandable source variants.
- Raw service output aperture.
- History and records accessible below.

The first current service may open by default when doing so reveals useful output and does not create excessive vertical displacement. Subsequent services remain collapsed.

When no banner exists, say `No source output`. Do not synthesize a banner from normalized fields.

Confirmed vulnerability red must remain visually isolated. A host with no confirmed vulnerabilities uses the neutral version of that panel.

### 9.5 Scans

Purpose: choose a scanner, review existing jobs, prepare commands, validate them, and launch authorized scans.

Required composition:

- `PROCESS CONTROL` manifest.
- Tool modules.
- Job queue/history.
- Persistent `New scan` action.

Each scanner module can use a two-digit index and a patterned corner. The module description must state what the profile actually does.

The scan page should feel like an equipment rack, not a pricing-card gallery.

### 9.6 Scan composer

Purpose: construct and review a safe, explicit scan job.

Required composition:

- Process-control heading.
- Target-buffer aperture.
- Scanner/profile selector.
- Editable target list.
- Relevant profile controls.
- Generated command draft.
- Warnings and validation.
- Explicit launch action after validation.

Before an exact command exists, the aperture may display truthful preparation state such as target count, source mode, and `LOCKED_UNTIL_VALIDATED`.

After preview, show the exact server-generated command. Do not present an approximate frontend command as executable truth.

Editable command text remains a review artifact under the current safety model. If editing disables execution, explain that adjacent to the command.

### 9.7 Evidence, imports, and timeline

These screens should use the same apparatus more lightly.

- Evidence records emphasize raw content and provenance.
- Imports emphasize artifact identity, parsing status, warnings, and original-file access.
- Timeline emphasizes time, command, operator, status, and output.

Raw content should receive the terminal material. Surrounding metadata should remain neutral.

### 9.8 Scope

Scope is an operational control surface. Keep include and exclude rules unmistakable. Decoration must never make an exclusion look like a warning that can be ignored.

Use red sparingly for destructive or blocking scope effects, amber for warnings, and neutral/inverse treatment for ordinary include rules.

### 9.9 Map

The globe remains blue. Orange marks ordinary host clusters. Red marks clusters containing confirmed vulnerabilities. Confirmed and non-confirmed clusters do not merge.

Map labels should prefer hostnames and include IP addresses as supporting identity. Clusters must remain readable at wide zoom levels.

Do not add animated star fields, rotating grids, ambient camera motion, or constant auto-rotation.

## 10. Raw-output policy

Raw output is both evidence and visual material. Treat it carefully.

### 10.1 Provenance

Every raw aperture should identify at least one of:

- Record ID.
- Job ID.
- Import filename.
- Scanner/tool.
- Observation time.
- Source owner.

### 10.2 Fidelity

Preserve original content as stored. Normalized summaries may sit above it, but should not silently rewrite the raw material.

If output was truncated during ingestion, label it as truncated. If output is absent, say so.

### 10.3 Safety and privacy

- Escape content before rendering.
- Keep raw artifacts behind authentication.
- Do not place credentials or the initial administrator password into screenshots, fixtures, documentation, or decorative readouts.
- Retain existing redaction behavior for command timelines.
- Do not move raw artifacts into public static directories.

### 10.4 Legibility

- Use at least 9px text on desktop.
- Use approximately 1.5–1.8 line height.
- Provide vertical scrolling for long content.
- Wrap JSON and banners when horizontal scrolling would obscure the owning record.
- Allow copying text normally.

## 11. Motion and interaction

Motion communicates an actual transition:

- Drawer opening.
- Host dossier appearing.
- Service expanding.
- Map focus changing.
- Job state updating.
- New evidence becoming available.

Motion should be brief, generally 80–180ms. Respect `prefers-reduced-motion`.

Never add:

- Fake boot sequences.
- Typewriter animation.
- Ambient glitch loops.
- Jitter.
- Parallax.
- Continuous marquee text.
- Automatic globe rotation.

Static texture provides atmosphere without making the tool tiring.

## 12. Responsive behavior

### 12.1 Desktop, 1440–1920px

- Keep the narrow rail visible.
- Use two-column Overview and host dossier layouts.
- Show at least six useful Explore records at 1600×1000.
- Let apparatus bands span the available work plane.
- Preserve the scan composer as a wide right drawer.

### 12.2 Compact desktop/tablet, 768–1100px

- Collapse nonessential clock and trailing band labels.
- Stack primary Overview regions when needed.
- Move Explore facets behind a disclosure.
- Hide large decorative serial blocks before hiding operational data.
- Keep local Explore tabs accessible.

### 12.3 Narrow/mobile, below 720px

- Convert the rail to a horizontal navigation strip.
- Stack manifest/aperture blocks vertically.
- Remove decorative repetitions and oversized background text.
- Preserve raw output, but constrain its height.
- Keep New scan reachable.

Responsive reductions remove apparatus before information.

## 13. Accessibility contract

Atmosphere does not excuse inaccessible controls.

- Maintain WCAG AA contrast for operational text and controls.
- Decorative low-contrast text must be marked `aria-hidden="true"` when it conveys no unique information.
- Every icon-only button needs an accessible label.
- Color cannot be the only indication of confirmed, passive, open, failed, or selected state.
- Native form behavior, selection, focus, and keyboard editing must remain intact.
- Focus indicators must be visible against both dark and inverse planes.
- Do not use CSS clipping that hides focus rings or essential text.
- Raw evidence must be selectable and readable by assistive technology.
- Respect reduced-motion preferences.
- Do not disable zoom.

## 14. Agent implementation protocol

An agent modifying Vandal's interface should follow this sequence.

### 14.1 Read before editing

1. Read this document.
2. Read `docs/uat-redesign.md` for current data hierarchy.
3. Inspect the target screen at desktop and narrow widths.
4. Identify which existing visual object the change belongs to: shell, signal band, aperture, identity plate, register, module, or ordinary control.
5. Confirm whether the change presents normalized state or raw evidence.

### 14.2 State the design intent

Before a substantial pass, record:

- The operator task.
- The emotional effect being pursued.
- The one or two apparatus gestures being added.
- Which data surfaces will remain quiet.
- Which semantic colors are involved.

If the plan contains five unrelated decorative ideas, simplify it.

### 14.3 Implement from existing primitives

Reuse current classes and tokens when possible:

- `.system-tape`
- `.workspace-signal`
- `.overview-transmission`
- `.scan-manifest`
- `.query-aperture`
- `.identity-aperture`
- `.raw-channel`
- `.composer-aperture`
- `.host-serial`
- `.tool-index`

Create a new primitive only when the object has a different semantic role.

Do not paste one-off inline styles across renderer strings. Put reusable visual rules in `vandal/static/app.css` or the owning stylesheet.

### 14.4 Use truthful data

Prefer values already returned by the owning API. If new data is needed, add it explicitly and test it.

Do not derive operational claims from decorative assumptions. Examples:

- A stored record count can appear in a system readout.
- `PROFILE_VALIDATION_REQUIRED` can appear because execution actually requires validation.
- `UPLINK SECURE` cannot appear unless the application has a defined and measured state with that meaning.

### 14.5 Preserve escaping

Renderer strings must pass all hostnames, banners, commands, filenames, user notes, errors, and source values through the existing `esc()` helper unless inserting a deliberately generated safe fragment.

Never place raw scanner output directly into `innerHTML`.

### 14.6 Cache-bust changed assets

When modifying a deployed static asset, update its query-string version in `vandal/templates/index.html`. Keep one coherent version label for a design pass.

### 14.7 Validate safely

For visual-only local review:

1. Start the local app on a separate port.
2. Set `VANDAL_WORKER=0`.
3. Use the local database or an explicit fixture.
4. Do not launch a scan.
5. Capture Overview, Explore, a representative host dossier, Scans, and the composer.
6. Capture at least one 768px-wide screen for responsive review.
7. Record console and page errors.
8. Inspect raw apertures for wrapping and escaping.

Visual review should include a host with many open services and one with confirmed vulnerabilities when available.

### 14.8 Deployment discipline

- Work on a branch.
- Commit the reviewed state.
- Create a remote rollback archive before overwriting deployed files.
- Transfer only intended code/static files.
- Do not transfer local databases, credentials, artifacts, or job state during a UI deployment.
- Restart the service.
- Verify hashes, asset version, HTTP response, and service logs.

## 15. Agent decision tests

Before adding an accent, ask:

1. Does it establish a material, subsystem, or mode?
2. Is it large enough to matter compositionally?
3. Does it use a color with the correct semantic meaning?
4. Does it leave the data itself easy to scan?
5. Is any operational claim truthful?
6. Does a similar primitive already exist?
7. Will it remain tolerable after eight hours of use?

If the answers are mostly no, omit it.

Before removing an accent, ask:

1. Is this one of the few elements creating the fictional world?
2. Would removing it leave an ordinary dark admin dashboard?
3. Can its intensity be reduced without eliminating its role?

Do not automatically remove an element merely because it is decorative.

## 16. Anti-pattern catalogue

### 16.1 Generic professional portal

Symptoms:

- Dark blue-gray background.
- Uniform rounded cards.
- A metric grid with one colored first card.
- Corporate sans-serif body type.
- Tiny icon plus heading plus explanatory copy in every card.
- Soft shadows and generous empty padding.

Correction: flatten the work surface, add one authored subsystem band, expose real output, and use stronger material contrast.

### 16.2 Generic cyberpunk dashboard

Symptoms:

- Neon outline around every panel.
- Cyan/magenta palette.
- Glowing borders.
- Hex grids.
- Random warning icons.
- Fake code rain.
- Constant glitch animation.

Correction: remove outlines and animation. Use broad blocks, restrained orange/green/blue/red semantics, and real scan material.

### 16.3 LLM landing-page design

Symptoms:

- Hero statement.
- Product slogan.
- Gradient orb or color splash.
- Three benefit cards.
- Pill badges everywhere.
- Explanatory reminder copy under every section.
- Repeated `Powerful`, `Unified`, `Intelligent`, or `Seamless` language.

Correction: begin with the operator's current system state and data. Remove pitch language.

### 16.4 Decoration by accumulation

Symptoms:

- Every panel has stripes.
- Every title has a serial number.
- Every row has a glowing arrow.
- Three different textures overlap.
- Decorative copy competes with values.

Correction: keep the strongest gesture near the screen entrance and the most useful raw aperture. Quiet the rest.

### 16.5 Fake terminal

Symptoms:

- Invented shell prompts.
- Random commands.
- Fake latency.
- Blinking cursor on static text.
- Green text applied to normalized prose.
- Scanner output reformatted until it no longer matches evidence.

Correction: use actual command drafts, banners, resolver answers, logs, and stored records.

### 16.6 False risk signaling

Symptoms:

- Potential CVEs shown in confirmed red.
- Passive port claims presented as verified open.
- Decorative warning color attached to ordinary counts.
- Map nodes colored by aesthetics instead of state.

Correction: restore the semantic color contract and explicit labels.

### 16.7 Hairline dependence

Symptoms:

- Every grouping relies on a 1px border.
- Tables resemble spreadsheets made from faint rules.
- Colored left borders identify all states.

Correction: use spacing, alternating planes, broad headers, and material changes.

## 17. Detailed review checklist

### Composition

- [ ] The first viewport contains one clear primary instrument or work region.
- [ ] There is at least one strong apparatus gesture.
- [ ] Apparatus occupies approximately 15% of the visual attention.
- [ ] Repeated records remain visually quiet.
- [ ] Empty space feels intentional rather than unfinished.
- [ ] The page does not read as a grid of interchangeable cards.

### Typography

- [ ] Fraktion Mono remains the default working face.
- [ ] Display typography is limited to titles, subsystem blocks, and decorative identifiers.
- [ ] Operational values are never obscured by oversized decorative type.
- [ ] Metadata is readable without zoom.
- [ ] Hostnames and commands retain their natural case.

### Color

- [ ] Orange indicates operator action or current mode.
- [ ] Green indicates raw output, completion, or verified open state.
- [ ] Blue is reserved for geographic/network projection.
- [ ] Red means confirmed vulnerability or blocking failure.
- [ ] Amber means uncertainty, passive evidence, or warning.
- [ ] Pale inverse planes remain rare.

### Raw material

- [ ] Raw excerpts come from retained evidence.
- [ ] Provenance is visible.
- [ ] Content is escaped.
- [ ] Long output wraps or scrolls.
- [ ] Missing output is labeled honestly.
- [ ] No credentials appear.

### Interaction

- [ ] New scan remains accessible.
- [ ] Explore state survives host inspection.
- [ ] Focus is visible.
- [ ] Standard form editing still works.
- [ ] No ambient animation distracts from reading.
- [ ] Confirmed and potential findings remain distinct.

### Density

- [ ] Explore shows at least six useful rows at 1600×1000.
- [ ] Padding was reduced before font size.
- [ ] Empty and zero states do not repeat excessively.
- [ ] Important values appear once in the correct hierarchy.
- [ ] Decoration does not force useful data below the fold without reason.

### Responsive

- [ ] Apparatus simplifies before information disappears.
- [ ] No page-wide horizontal overflow exists at 768px.
- [ ] Drawers remain closable and scrollable.
- [ ] Raw output remains usable.
- [ ] The primary action remains reachable.

### Deployment

- [ ] Static asset versions were updated.
- [ ] Browser console has no new errors.
- [ ] No scan was launched during screenshot review.
- [ ] The branch is committed.
- [ ] A remote rollback archive exists before deployment.
- [ ] Remote code hashes and service health were verified.

## 18. Extension recipes

### 18.1 Adding a new scanner

1. Add it as a module within Process Control.
2. Assign the next stable two-digit visual index.
3. Use its actual tool name and installation state.
4. Give it a concise capability description.
5. Add a profile-specific composer section.
6. Show truthful pre-validation state in the aperture.
7. Replace preparation state with the exact generated command after preview.
8. Expose raw output and artifacts in the job detail.
9. Keep tool-specific decoration subordinate to Vandal's shared orange/green system.

### 18.2 Adding a new host evidence type

1. Normalize its current-state summary into the owning host section.
2. Preserve the original record.
3. Add provenance and observation time.
4. Use an expandable raw aperture if the source contains meaningful raw material.
5. Apply active/passive precedence consistently.
6. Do not create a new global color unless the state cannot use the existing semantics.

### 18.3 Adding a new Explore mode

1. Add it to the existing local workspace tabs.
2. Preserve search/selection state where relevant.
3. Reuse the Surface Index band.
4. Give the mode one distinguishing instrument or raw-material treatment.
5. Keep global navigation unchanged unless the destination is genuinely global.

### 18.4 Adding a major empty state

1. State what is absent.
2. Provide the one direct action that resolves it.
3. Use a restrained apparatus mark if the region would otherwise feel unfinished.
4. Do not use an illustration, product pitch, or celebratory copy.

### 18.5 Adding an error state

1. State the failed operation.
2. Show the actual error or a safe retained excerpt.
3. Identify whether existing data remains valid.
4. Provide retry, inspect output, or return actions.
5. Use red only when the operation is truly blocked or failed.

## 19. Current approved motifs

These motifs form the baseline visual language and should remain recognizable unless the user changes direction:

- Orange `V/` shell mark.
- Orange global external-surface tape.
- Green Control Bus rail label.
- Block-pattern dark substrate.
- Large low-contrast `VNDL/SYS` page marking.
- Orange Surface and Process Control title blocks.
- Green Surface Index band in Explore.
- `QUERY://` black-green search aperture.
- Pale host identity plate with striped serial block.
- Green raw service-output wells.
- Two-digit scan module indices.
- Orange Scan Control block in the composer.
- Blue globe, orange ordinary clusters, red confirmed-vulnerability clusters.

This list is a foundation, not a requirement to place every motif on every page.

## 20. Final standard

A successful Vandal screen should pass three tests:

1. **Operational test:** Can the assessor complete the task quickly and understand the evidence hierarchy?
2. **Fiction test:** Would a still image be recognizable as a specialized fictional technical system rather than a generic web dashboard?
3. **Endurance test:** Can the screen remain open during real work without animation, contrast, texture, or repetition becoming exhausting?

When these tests conflict, preserve operational truth first, then solve the visual problem with composition and material rather than removing Vandal's character.
