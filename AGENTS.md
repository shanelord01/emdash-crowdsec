# emdash-crowdsec

CrowdSec for EmDash: the package `emdash-crowdsec`, and
`@shane.bsky.shas.am/emdash-crowdsec` in the EmDash registry once it is
published there. It reads a CrowdSec Local API (LAPI) with a machine login,
can add and remove decisions when Allow changes is on, and has a demo data
source.

Before editing this plugin, read `skills/creating-plugins/SKILL.md` completely. Codex discovers the same directory through `.agents/skills`. Claude discovers it through `.claude/skills` and reads these instructions through `.claude/CLAUDE.md`.
Keep `emdash-plugin.jsonc` aligned with the runtime implementation, declare every capability and host the plugin uses, and run the generated validation, typecheck, test, and build scripts after changes.

## Toolchain

`emdash` is a peer with a floor and no ceiling (`>=1.0.1`, the same as
`env:emdash` in the manifest). Never write the floor as `>=1.0.0` or
`^1.0.0`: npm carries an accidental, deprecated `emdash@1.0.0` published
in April 2026, five months before the real 1.0. The dev dependency resolves
to 1.0.1, the host `@emdash-cms/plugin-test@0.2.6` pins, so typecheck and
tests see the same EmDash. Built with `@emdash-cms/plugin-cli@0.13.1`,
`@emdash-cms/plugin-test@0.2.6` and `@emdash-cms/blocks@1.0.1`.
`scripts/compat-matrix.sh` runs the suite against later EmDash releases. A
plain `pnpm install` is enough.

## Things that will bite

- **Count your bridge calls.** A sandboxed invocation gets ten
  subrequests and every `ctx` call spends one, `log`, `kv` and `cron`
  included. The sync, the setup check and the cold-cache DNS refresh use
  exactly ten. `tests/budget.test.ts` counts each invocation's worst case:
  run it after any change that adds a `ctx` call or a LAPI request.
- **LAPI has no offset.** `GET /v1/alerts` takes `since` and `until` as
  durations back from LAPI's now, filters on each alert's start time and
  answers newest created first, up to `limit`. Paging is done by moving
  the window to the oldest creation time in a full answer
  (`src/sync/scheduler.ts`). Never read an unbounded range: an answer over
  8 MiB throws inside `ctx.http.fetch`.
- **Unusable settings never wipe.** `runSync` returns on `!result.ok`
  before it compares datasets. A refused URL, an unknown time zone or a
  cleared password pauses the sync and keeps the rows: LAPI flushes its own
  alerts, so stored history may be the only copy. Only valid settings that
  describe another dataset start a wipe. `tests/robustness.test.ts` covers it.
- **The lease guards the last write too.** A tick claims the state with a
  conditional write and writes its result against the revision it claimed.
  A tick that overran its lease has its write discarded.
- **LAPI includes the community blocklist unless told not to.** Every
  search sends `include_capi=false` except a lookup of one address
  (`blocklists: "include"`) and the daily count (`origin=CAPI`/`lists`). On a
  live site the blocklist was 71 alerts, 24,004 decisions and 3.5 MB.
  `isBlocklistAlert` and `isBlocklistDecision` (`src/lapi/blocklist.ts`)
  keep it out of every count even when LAPI sends it. 0.1.0 took out the rows a
  pre-release build stored (`runPurge`, removed in 0.1.1 once every 0.1.0
  install had run it).
- **Self-hosted only.** Everything comes from the site's own LAPI and
  Prometheus endpoints. Never call CrowdSec's cloud or Service API.
- **Metrics are counters that reset.** `src/metrics/sample.ts` keeps the
  last raw sample and stores differences, a drop being a reset. The first
  sample is a baseline, and a source that was down at the baseline starts
  its own. The sampler is its own cron task (`metrics`, seven calls),
  because the sync tick has no calls to spare. It runs only for a LAPI
  source with a metrics URL (`samplerOn`): a sync tick that finds that
  changed schedules or cancels it. Demo traffic is worked out when read
  (`src/metrics/demo.ts`), with nothing sampled or stored.
- **One action id per button.** A shared `action_id` makes React warn about
  duplicate keys. Range buttons are `cs:range:24h`, `cs:range:7d` and so on,
  and row buttons carry the row's id.
- **Never `ip=`.** It also matches alerts with an empty source. Search by
  `scope` and `value`.
- **The User-Agent is load-bearing.** LAPI refuses a login whose
  User-Agent is not `name/version` with the same 401 a wrong password gets.
  `src/version.ts` holds it, and `tests/version.test.ts` keeps it equal to
  `package.json`.
- **No token in KV.** Each invocation that needs LAPI logs in once. Do not
  add a token cache back: plugin KV is readable by anything that reads the
  plugin's state, and the budget fits without one.
- **Writes are checked in the handler.** EmDash sends every admin page and
  widget interaction to the `admin` route, which is `plugins:read` so
  editors can see the pages. Every write therefore checks
  `routeCtx.user.role` for the administrator role through `writeGate`
  (`src/write/actions.ts`). The MCP write tools have their own
  `plugins:manage` routes, which the host enforces.
- **The ban protections are the point.** `src/net/ip.ts` and
  `src/net/protect.ts`. Add a refusal there, never around them, and add a
  test that fails without it.
- **Deleting an alert deletes its decisions where bouncers never hear of
  it.** The guard refuses while any decision is active, ended under two
  minutes ago, or has an end time that cannot be read.
- **Days are local.** Every day key, range, retention cut-off and label is
  in the Time zone setting. `src/time/zone.ts` is shared word for word with
  emdash-to-buffer-plus. Change it there first and copy it, so both plugins
  draw the same day boundaries.
- **Charts are `custom`, not `timeseries`.** A timeseries tooltip shows a
  day as a timestamp in the viewer's zone. `dailyChart` in
  `src/ui/blocks.ts` uses a category axis of day labels.
- **Alerts live in the alert log, not one row each.** `src/store/log.ts`.
  A sync step writes one chunk per local day without a read, and the
  hourly `reconcile` task (`runMaintenance`) merges a hundred chunks into
  day parts, or at 3 am local time runs the prune. The `alerts`
  collection only holds rows 0.1.0 stored until `runMigrate` moves them.
  A deleted alert is taken out of its day's log rows (`removeFromLog`).
- **The nightly prune shares its batches.** `runReconcile` has four
  query-and-delete batches for every collection together, so a store with
  many old rows can leave some for the next night. It catches up within a
  few nights, so this is left as it is.
- **A Block Kit answer holds 2,000 JSON nodes at most.** The host refuses
  a bigger one with a 502. Charts cost a node per point per series, so
  the 90-day CrowdSec page draws three days a bar, the explorer caps day
  histograms at 45 bars and its filter selects at twelve options, and
  `tests/pages.test.ts` renders every explorer view under 1,900.
- **Demo writes change nothing.** `writeMode` gives administrators the
  write controls on demo data without Allow changes, the review runs
  `checkBan` with no DNS lookup, and every write answers
  `demoNothingChanged`. Never send a request for demo data.
- **Block Kit keys are snake_case.** Use the constructors in
  `src/ui/blocks.ts`. The renderer silently ignores camelCase.
- **MCP schemas never reach the runtime.** `src/tools/declare.ts` is
  referenced only from `mcp` in `src/plugin.ts`, which the build strips, so
  zod stays a dev dependency. Output schemas are strict, and
  `tests/tools.test.ts` checks each answer against the one the build wrote.
- **Block Kit keeps no state.** Filters, sort order and positions travel in
  action ids, button values and table cursors. The explorer's whole view
  rides after a `|` in every action id (`src/explorer/model.ts`), and the
  control's role before it, so no two ids repeat.
- **Test URLs match to the character.** `respondSearch` in `tests/host.ts`
  answers every URL a run could build over a few seconds, since `since` and
  `until` come from the run's clock.

## Conventions

- Tabs. English in code, comments and docs, Australian spelling in
  anything a person reads.
- No em or en dashes, no semicolons joining clauses.
- ESM: internal imports carry `.js`, and types come in with `import type`.
- Anything that talks HTTP takes an injected `fetch`. Whole invocations go
  through the test host's `host.http.respond()`.
- A test must be able to fail on a real regression.

## Checks

```sh
pnpm install
pnpm typecheck
pnpm test        # emdash-plugin validate, then vitest
pnpm build
pnpm bundle
./scripts/compat-matrix.sh 1.0.1
```

## Releases

Publishing is done by hand, by the owner only, from a machine that is
logged in to the registry:

```sh
pnpm registry:login     # once per machine
pnpm registry:publish   # builds, bundles and publishes to the EmDash registry
```

`package.json` is `private`, so nothing can be published to npm by
accident. While it is, `changeset version` leaves the package alone: bump
`version` in `package.json` and `src/version.ts`, and add the `CHANGELOG.md`
entry by hand. Add a changeset with `pnpm changeset` for every change that
ships, written for someone upgrading.

The registry page's tabs are `docs/registry/*.md`, declared under
`sections` in the manifest. Each is capped at 20000 bytes and 2000
graphemes, and the manifest `description` at 140 graphemes, which
`emdash-plugin validate` does not check. `tests/docs.test.ts` checks all
three.

Never name a script `publish`, `version` or `prepare`: npm and pnpm run
those on their own during a publish or a version bump.
