/**
 * The sync job.
 *
 * Three limits decide its shape:
 *
 * 1. **Ten bridge calls per sandboxed invocation.** Every `ctx` call is
 *    one, `log` included, and the eleventh aborts the invocation on
 *    Cloudflare. Each step below is annotated with its count, and
 *    `tests/budget.test.ts` counts the worst case of each. No tick logs: a
 *    failure is recorded in the sync state, where the widget shows it.
 * 2. **8 MiB per response.** `ctx.http.fetch` buffers the whole body and
 *    throws past 8 MiB. An alert averages about 13 KB in LAPI's JSON, so a
 *    search is bounded twice: by a time window and by `limit` (`batch`, 200
 *    to start). An answer over the cap halves the batch for the next try,
 *    down to `MIN_BATCH`, and successful steps grow it back.
 * 3. **No retry.** A failed tick is recorded and the next one starts from
 *    the stored state, never assuming the previous one ran.
 *
 * LAPI's alert search has no offset. It takes `since` and `until` as
 * durations back from LAPI's now, filters on each alert's start time and
 * answers newest created first, up to `limit`. So the sync keeps:
 *
 * - `head`: when the last forward step ran. A forward step reads the last
 *   24 hours (or from an hour before `head`, if that is further back).
 *   Its batch is full only when even its oldest alert was created after
 *   the previous head: then alerts between the two were not reached, and
 *   that span becomes a gap.
 * - `gaps`: time ranges still to read, newest first. A backfill step reads
 *   the newest 30 days of the newest gap at most. When the batch fills,
 *   the gap shrinks to end at the oldest creation time in the answer. An
 *   alert's start is never after its creation, so nothing unread is
 *   skipped. When it does not fill, the step's window is done.
 *
 * The first sync opens a gap from the retention limit to now, so the
 * newest alerts arrive first and history fills in behind them.
 *
 * Windows overlap on purpose, so an alert can arrive twice. Rows are stored
 * by alert id, and each day row records the ids it has counted, so an
 * alert is counted once whichever window brings it.
 *
 * Durations are measured on LAPI's clock: each response's Date header
 * gives the skew between the two, which is kept for the next tick.
 *
 * A tick takes a lease in the state before it works, with a conditional
 * write, so the recurring sync and a chained catch-up run never work on
 * the same state at once. A tick that finds the lease taken does nothing.
 */

import type { PluginContext } from "emdash/plugin";

import { failure, type Problem } from "../i18n.js";
import { compactAlert, countInto, emptyDay, trimDay, type AlertRow, type DayRow, type Kind } from "../store/rows.js";
import { alertsStore, daysStore, ID_BATCH } from "../store/access.js";
import { DNS_KEY, dnsFresh, isLocalName, namesToResolve, resolveNames, type DnsCache } from "../net/protect.js";
import { datasetOf, readSettings, type CrowdSecSettings } from "../settings.js";
import { buildSource, type Source } from "../sources.js";
import { addDays, dayStart, hourKey, hourStart, localDay, parseGoDuration } from "./time.js";

export const SYNC_TASK = "sync";
export const RECONCILE_TASK = "reconcile";
/** The one-shot a Refresh schedules: a forward step out of turn. */
export const REFRESH_TASK = "refresh";
/** The one-shot a write schedules: the active ban count, read again. */
export const BANS_TASK = "bans";
/** Chained one-shots while history is being read. Two names, because a one-shot is deleted when its run returns. */
export const CATCH_UP_TASKS = ["catchup-a", "catchup-b"] as const;
export const RECONCILE_SCHEDULE = "10 3 * * *";

export const KV_PREFIX = "sync.";
export const STATE_KEY = "sync.state";
/** When the dashboard first found the sync scheduled and not yet run. */
export const WAITING_KEY = "sync.waiting";

export const DEFAULT_BATCH = 200;
export const MIN_BATCH = 20;
/** The largest batch a backfill step grows to when one second holds more alerts than the batch. About 6.5 MB on average. */
export const MAX_BATCH = 500;
/** The longest time span one backfill search covers. Bounds the days one step touches. */
export const MAX_SPAN_MS = 30 * 86_400_000;
/** How far back every forward step reads. */
export const FORWARD_REACH_MS = 24 * 3_600_000;
/** And at least this far before the previous head. */
export const FORWARD_OVERLAP_MS = 3_600_000;
/** Alerts read for the active ban count at first, about 1.3 MB at an average alert's size. */
export const ACTIVE_BATCH = 100;
/** How long a tick's lease lasts: longer than the cron hook's 30 s timeout. */
export const LEASE_MS = 90_000;
/** Hours the widget's buckets cover: 24 shown, 24 before them to compare. */
const HOURS_KEPT = 48;
const SCENARIOS_PER_HOUR = 10;

/** One sync step. Ticks rotate through these four slots. */
const SLOTS = ["forward", "backfill", "bans", "backfill"] as const;

export const CATCH_UP_DELAY_MS = 50_000;
const CATCH_UP_PENDING_MS = 5 * 60_000;

export interface Gap {
	/** ISO times: alerts that started in [from, to] are still to read. */
	from: string;
	to: string;
}

export interface HourBucket {
	alerts: number;
	waf: number;
	bot: number;
	behaviour: number;
	manual: number;
	scenarios: Record<string, number>;
}

export interface ActiveSnapshot {
	/** Distinct addresses and ranges with an unexpired ban. */
	bans: number;
	/** Unexpired decisions of any type. */
	decisions: number;
	at: string;
	/** True when the read filled its batch, so there may be more. */
	truncated: boolean;
}

export interface SyncState {
	dataset?: string;
	head?: string;
	gaps?: Gap[];
	/** The start of the oldest local day kept, when last set. */
	floor?: string;
	batch?: number;
	/** The batch of the active ban read. */
	activeBatch?: number;
	/** LAPI's clock less ours, in milliseconds, from the last Date header. */
	skewMs?: number;
	slot?: number;
	lastSync?: string;
	lastError?: string;
	lastProblem?: Problem;
	lastErrorAt?: string;
	hours?: Record<string, HourBucket>;
	active?: ActiveSnapshot;
	chain?: { next: string; at: string };
	/** Held by the tick working on the state. */
	lease?: { owner: string; until: string };
	/** The gap end a backfill batch was grown for, because one second there held more alerts than the batch. */
	burst?: string;
	/** After a failed DNS lookup for the ban protections, when to try again. */
	dnsRetryAt?: string;
}

/** What a route reads in one call: the state, the DNS cache and the waiting mark share the `sync.` prefix. */
export interface Loaded {
	state: SyncState;
	dns: DnsCache | null;
	waiting: string | null;
}

export async function loadKv(ctx: PluginContext): Promise<Loaded> {
	const values = new Map<string, unknown>();
	for (const entry of await ctx.kv.list(KV_PREFIX)) values.set(entry.key, entry.value);
	return {
		state: (values.get(STATE_KEY) as SyncState | undefined) ?? {},
		dns: (values.get(DNS_KEY) as DnsCache | undefined) ?? null,
		waiting: (values.get(WAITING_KEY) as string | undefined) ?? null,
	};
}

/** Schedule the sync and the daily prune. `schedule` upserts on (plugin, task), so repeating it is harmless. */
export async function ensureScheduled(ctx: PluginContext, interval: string): Promise<void> {
	if (!ctx.cron) return;
	try {
		await ctx.cron.schedule(SYNC_TASK, { schedule: interval });
		await ctx.cron.schedule(RECONCILE_TASK, { schedule: RECONCILE_SCHEDULE });
	} catch {
		// An unscheduled sync shows on the setup check. A route must still render.
	}
}

/** Ask for a one-shot run instead of running a sync step inside an admin request. False without a scheduler. */
export async function requestTask(ctx: PluginContext, task: string, now: Date): Promise<boolean> {
	if (!ctx.cron) return false;
	await ctx.cron.schedule(task, { schedule: now.toISOString() });
	return true;
}

/** Remember when the dashboard first found the sync waiting, so the setup check can tell a scheduler that never runs. */
export async function noteWaiting(ctx: PluginContext, loaded: Loaded, now: Date): Promise<void> {
	if (loaded.state.lastSync || loaded.waiting) return;
	await ctx.kv.set(WAITING_KEY, now.toISOString());
}

export interface SyncOutcome {
	step: "forward" | "backfill" | "bans" | "dns" | "wipe" | "idle" | "busy";
	ok: boolean;
	/** Alerts counted for the first time. */
	counted: number;
	problem?: Problem;
}

export type SyncMode = "scheduled" | "refresh" | "bans" | "catchup";

/**
 * One tick.
 *
 * Calls: kv.getVersioned and kv.compareAndSet for the lease,
 * settings.list, then the step, then kv.set of the state.
 *
 * - forward and backfill: the login, the search, days.getMany,
 *   alerts.putMany, days.putMany: nine with the four around them, and a
 *   chained catch-up run's cron.schedule makes ten.
 * - bans: the login and the search: six.
 * - dns: kv.get of the cache, two requests per hostname for two
 *   hostnames at most, and the cache write: ten. When the lookup leaves
 *   room for the login, the search and the state write, the ban count
 *   follows in the same tick.
 * - busy (the lease is held): the read and the claim, and a Refresh or a
 *   ban count scheduled again: three.
 */
export async function runSync(ctx: PluginContext, now: Date = new Date(), mode: SyncMode = "scheduled", task?: string): Promise<SyncOutcome> {
	const versioned = await ctx.kv.getVersioned<SyncState>(STATE_KEY);
	let state: SyncState = versioned?.value ?? {};
	if (state.lease && Date.parse(state.lease.until) > now.getTime()) return await busy(ctx, mode, now);
	const lease = { owner: crypto.randomUUID(), until: new Date(now.getTime() + LEASE_MS).toISOString() };
	const claim = await ctx.kv.compareAndSet(STATE_KEY, versioned?.revision ?? null, { ...state, lease });
	if (!claim.applied) return await busy(ctx, mode, now);
	revisions.set(ctx, claim.revision);

	const result = await readSettings(ctx);
	// Settings that cannot be used (a refused URL, an unknown time zone,
	// a missing password) stop the sync and touch nothing stored: they
	// describe no dataset, so they must never read as a change of one.
	if (!result.ok) return await fail(ctx, state, "idle", now, result.problem);
	const settings = result.settings;

	// Rows from one LAPI, read with simulated alerts or counted in another
	// time zone must not be read as these settings' rows. A dataset changed
	// by valid settings clears the store before anything else.
	const dataset = datasetOf(settings);
	if (state.dataset && state.dataset !== dataset) return await runWipe(ctx, state, now);

	const source = buildSource(ctx, settings, state.skewMs, { now: () => now });
	if (!source) return await fail(ctx, state, "idle", now, failure("noNetwork").problem);

	state = { ...state, dataset, gaps: clipGaps(state, settings, now) };

	if (mode === "bans") return await runBans(ctx, source, settings, state, now);

	// The first step opens one gap over the whole retention window and
	// reads its newest end.
	if (!state.head) {
		const first = { ...state, head: now.toISOString(), gaps: [{ from: floorOf(settings, now), to: now.toISOString() }] };
		return await runBackfill(ctx, source, settings, first, now, mode, task);
	}

	if (mode === "refresh") return await runForward(ctx, source, settings, state, now);
	if (mode === "catchup") {
		if ((state.gaps ?? []).length === 0) {
			await writeState(ctx, state);
			return { step: "idle", ok: true, counted: 0 };
		}
		return await runBackfill(ctx, source, settings, state, now, mode, task);
	}

	const slot = SLOTS[(state.slot ?? 0) % SLOTS.length]!;
	state = { ...state, slot: ((state.slot ?? 0) + 1) % SLOTS.length };
	if (slot === "bans") {
		// Local names (localhost, a name without a dot) cannot be looked up
		// over DNS over HTTPS. The setup check names them and bans stay
		// refused, so the sync does not try them every hour.
		const names = namesToResolve(ctx.site.url, settings.lapiUrl).filter((name) => !isLocalName(name));
		const retry = state.dnsRetryAt === undefined || Date.parse(state.dnsRetryAt) <= now.getTime();
		if (settings.allowChanges && ctx.http && names.length > 0 && retry) {
			const dns = await ctx.kv.get<DnsCache>(DNS_KEY);
			if (!dnsFresh(dns, names, now)) {
				const looked = await refreshDns(ctx, names, now);
				// The ban count still runs when the calls left cover it: the
				// login, the search and the state write.
				if (looked.requests + (looked.ok ? 1 : 0) + 4 + 3 > 10) {
					await writeState(ctx, looked.ok ? state : { ...state, dnsRetryAt: retryAt(now) });
					return { step: "dns", ok: looked.ok, counted: 0 };
				}
				if (!looked.ok) state = { ...state, dnsRetryAt: retryAt(now) };
			}
		}
		return await runBans(ctx, source, settings, state, now);
	}
	if (slot === "backfill" && (state.gaps ?? []).length > 0) {
		return await runBackfill(ctx, source, settings, state, now, mode, task);
	}
	return await runForward(ctx, source, settings, state, now);
}

/** The start of the oldest local day the retention keeps. */
export function floorOf(settings: Pick<CrowdSecSettings, "retentionDays" | "timeZone">, now: Date): string {
	const zone = settings.timeZone;
	return new Date(dayStart(addDays(localDay(now, zone), -settings.retentionDays), zone)).toISOString();
}

/**
 * Gaps inside the retention window, newest first. A retention made longer
 * since the last tick opens a gap over the days it added.
 */
export function clipGaps(state: SyncState, settings: Pick<CrowdSecSettings, "retentionDays" | "timeZone">, now: Date): Gap[] {
	const floor = floorOf(settings, now);
	const gaps = (state.gaps ?? [])
		.filter((gap) => gap.to > floor)
		.map((gap) => (gap.from < floor ? { ...gap, from: floor } : gap));
	if (state.head && state.floor && floor < state.floor && Date.parse(state.floor) - Date.parse(floor) > 3_600_000) {
		gaps.push({ from: floor, to: state.floor });
	}
	return gaps.sort((a, b) => (a.to < b.to ? 1 : a.to > b.to ? -1 : 0));
}

/** The batch for the next try: half after an answer over the 8 MiB cap, down to `MIN_BATCH`. */
export function batchAfter(batch: number, problem: string): number {
	return problem === "tooLarge" ? Math.max(MIN_BATCH, Math.floor(batch / 2)) : batch;
}

/** After a step that fit: back towards the default, never past it. */
export function batchGrown(batch: number, ceiling = DEFAULT_BATCH): number {
	return batch >= ceiling ? batch : Math.min(ceiling, batch * 2);
}

interface StepResult {
	returned: number;
	counted: number;
	/** The oldest creation time in the answer, ISO. */
	oldestCreated?: string;
}

/**
 * One search, counted into the store.
 *
 * Calls: the search (with the invocation's login), days.getMany, then
 * alerts.putMany and days.putMany when anything is new. The alert rows are
 * written before the days that count them: a tick that dies between the
 * two leaves rows the next window counts, never a count without its rows.
 */
async function step(
	ctx: PluginContext,
	source: Source,
	settings: CrowdSecSettings,
	state: SyncState,
	now: Date,
	batch: number,
	since: Date,
	until: Date | undefined,
): Promise<{ ok: true; value: StepResult; state: SyncState } | { ok: false; problem: Problem; state: SyncState }> {
	const res = await source.alerts({ since, ...(until && { until }), limit: batch, simulated: settings.includeSimulated });
	const measured = withSkew(state, source);
	if (!res.ok) return { ok: false, problem: res.problem, state: { ...measured, batch: batchAfter(batch, res.problem.key) } };

	const rows: AlertRow[] = [];
	let oldestCreated: string | undefined;
	for (const raw of res.value) {
		const row = compactAlert(raw, now, settings.timeZone);
		if (!row) continue;
		if (!oldestCreated || row.createdAt < oldestCreated) oldestCreated = row.createdAt;
		if (row.simulated && !settings.includeSimulated) continue;
		rows.push(row);
	}

	const days = daysStore(ctx);
	const alerts = alertsStore(ctx);
	if (!days || !alerts) return { ok: false, problem: failure("storageUnavailable").problem, state: measured };

	const dayIds = [...new Set(rows.map((row) => row.day))];
	const existing = dayIds.length > 0 ? await days.getMany(dayIds) : new Map<string, DayRow>();
	const touched = new Map<string, DayRow>();
	const fresh: AlertRow[] = [];
	const hours = { ...(state.hours ?? {}) };
	const hourFloor = now.getTime() - HOURS_KEPT * 3_600_000;

	for (const row of rows.sort((a, b) => a.id - b.id)) {
		const day = touched.get(row.day) ?? structuredClone(existing.get(row.day) ?? emptyDay(row.day, now));
		if (!countInto(day, row)) continue;
		day.updatedAt = now.toISOString();
		touched.set(row.day, day);
		fresh.push(row);
		if (Date.parse(row.startedAt) >= hourFloor) addToHour(hours, row);
	}

	if (fresh.length > 0) {
		await alerts.putMany(fresh.map((row) => ({ id: String(row.id), data: row })));
		await days.putMany([...touched.values()].map((day) => ({ id: day.date, data: trimDay(day) })));
	}

	return {
		ok: true,
		value: { returned: res.value.length, counted: fresh.length, ...(oldestCreated && { oldestCreated }) },
		state: { ...measured, hours: pruneHours(hours, now) },
	};
}

function withSkew(state: SyncState, source: Source): SyncState {
	const skew = source.skew();
	return skew === undefined ? state : { ...state, skewMs: skew };
}

function addToHour(hours: Record<string, HourBucket>, row: AlertRow): void {
	const key = hourKey(Date.parse(row.startedAt));
	const bucket = hours[key] ?? { alerts: 0, waf: 0, bot: 0, behaviour: 0, manual: 0, scenarios: {} };
	bucket.alerts++;
	bucket[row.kind]++;
	if (row.scenario) bucket.scenarios[row.scenario] = (bucket.scenarios[row.scenario] ?? 0) + 1;
	hours[key] = bucket;
}

function pruneHours(hours: Record<string, HourBucket>, now: Date): Record<string, HourBucket> {
	const floor = now.getTime() - HOURS_KEPT * 3_600_000 - 3_600_000;
	const out: Record<string, HourBucket> = {};
	for (const [key, bucket] of Object.entries(hours)) {
		if (hourStart(key) < floor) continue;
		const top = Object.entries(bucket.scenarios)
			.sort((a, b) => b[1] - a[1])
			.slice(0, SCENARIOS_PER_HOUR);
		out[key] = { ...bucket, scenarios: Object.fromEntries(top) };
	}
	return out;
}

/** Read the last 24 hours. A full batch whose oldest alert is newer than the previous head leaves a gap. */
async function runForward(ctx: PluginContext, source: Source, settings: CrowdSecSettings, state: SyncState, now: Date): Promise<SyncOutcome> {
	const head = Date.parse(state.head!);
	// A sync stopped for weeks: the time since is history, read as a gap.
	if (now.getTime() - head > MAX_SPAN_MS) {
		const gaps = [{ from: state.head!, to: now.toISOString() }, ...(state.gaps ?? [])];
		return await runBackfill(ctx, source, settings, { ...state, head: now.toISOString(), gaps }, now, "refresh");
	}
	const since = new Date(Math.max(Math.min(head - FORWARD_OVERLAP_MS, now.getTime() - FORWARD_REACH_MS), Date.parse(floorOf(settings, now))));
	const batch = state.batch ?? DEFAULT_BATCH;
	const res = await step(ctx, source, settings, state, now, batch, since, undefined);
	if (!res.ok) return await fail(ctx, res.state, "forward", now, res.problem);

	// Newest created first: the batch reached everything new unless even its
	// oldest alert was created after the previous head.
	const oldest = res.value.oldestCreated;
	const full = res.value.returned >= batch && oldest !== undefined && Date.parse(oldest) > head;
	const gaps = full ? [{ from: since.toISOString(), to: oldest! }, ...(res.state.gaps ?? [])] : (res.state.gaps ?? []);
	await writeState(ctx, {
		...succeeded(res.state, now),
		head: now.toISOString(),
		gaps,
		floor: floorOf(settings, now),
		batch: full ? batch : batchGrown(batch),
	});
	return { step: "forward", ok: true, counted: res.value.counted };
}

/** Read the newest part of the newest gap, at most `MAX_SPAN_MS` of it. */
async function runBackfill(
	ctx: PluginContext,
	source: Source,
	settings: CrowdSecSettings,
	state: SyncState,
	now: Date,
	mode: SyncMode,
	task?: string,
): Promise<SyncOutcome> {
	const [gap, ...rest] = state.gaps ?? [];
	if (!gap) return await runForward(ctx, source, settings, state, now);
	const to = Date.parse(gap.to);
	const from = Math.max(Date.parse(gap.from), to - MAX_SPAN_MS);
	const batch = state.batch ?? DEFAULT_BATCH;

	const res = await step(ctx, source, settings, state, now, batch, new Date(from), new Date(to));
	if (!res.ok) {
		// A batch grown for a burst came back too large: no batch that fits
		// holds that second, so the gap steps past it.
		if (res.problem.key === "tooLarge" && state.burst === gap.to) {
			const stepped = to - 1000 > Date.parse(gap.from) ? [{ from: gap.from, to: new Date(to - 1000).toISOString() }, ...rest] : rest;
			return await fail(ctx, { ...res.state, gaps: stepped, burst: undefined }, "backfill", now, res.problem);
		}
		return await fail(ctx, res.state, "backfill", now, res.problem);
	}

	let nextBatch = batchGrown(batch);
	let burst: string | undefined;
	let remaining: Gap | null;
	if (res.value.returned >= batch && res.value.oldestCreated) {
		// The newest `batch` alerts of the window came back. Everything older
		// started no later than the oldest creation time among them.
		let next = Date.parse(res.value.oldestCreated);
		nextBatch = batch;
		if (next >= to) {
			// More alerts created in one second than the batch holds. Ask for
			// a bigger batch first. Past `MAX_BATCH`, step a second back: LAPI
			// has no offset to page through such a burst.
			if (batch < MAX_BATCH) {
				nextBatch = Math.min(MAX_BATCH, batch * 2);
				next = to;
				burst = gap.to;
			} else {
				next = to - 1000;
			}
		}
		remaining = next > Date.parse(gap.from) ? { from: gap.from, to: new Date(next).toISOString() } : null;
	} else {
		remaining = from > Date.parse(gap.from) ? { from: gap.from, to: new Date(from).toISOString() } : null;
	}
	const gaps = remaining ? [remaining, ...rest] : rest;

	let next: SyncState = { ...succeeded(res.state, now), gaps, floor: floorOf(settings, now), batch: nextBatch, burst };
	const chain = chainFor(next, now, mode, task, Boolean(ctx.cron));
	if (chain) next = { ...next, chain };
	await writeState(ctx, next);
	if (chain) await ctx.cron!.schedule(chain.next, { schedule: chain.at });
	return { step: "backfill", ok: true, counted: res.value.counted };
}

/**
 * While gaps remain, a backfill step schedules the next one a little under
 * a minute later instead of waiting for the sync's next turn. A chained
 * run continues its chain. A scheduled one starts a chain when none is
 * pending. The lease keeps a chained run and the sync apart.
 */
function chainFor(state: SyncState, now: Date, mode: SyncMode, task: string | undefined, cron: boolean) {
	if (!cron || (state.gaps ?? []).length === 0) return null;
	const at = new Date(now.getTime() + CATCH_UP_DELAY_MS).toISOString();
	if (mode === "catchup") return { next: task === CATCH_UP_TASKS[0] ? CATCH_UP_TASKS[1] : CATCH_UP_TASKS[0], at };
	if (mode !== "scheduled") return null;
	if (state.chain && now.getTime() < Date.parse(state.chain.at) + CATCH_UP_PENDING_MS) return null;
	return { next: state.chain?.next ?? CATCH_UP_TASKS[0], at };
}

/** Count the active bans: alerts with an unexpired decision, `activeBatch` at most. */
async function runBans(ctx: PluginContext, source: Source, settings: CrowdSecSettings, state: SyncState, now: Date): Promise<SyncOutcome> {
	const batch = state.activeBatch ?? ACTIVE_BATCH;
	const res = await source.alerts({ activeOnly: true, limit: batch, simulated: settings.includeSimulated });
	const measured = withSkew(state, source);
	if (!res.ok) return await fail(ctx, { ...measured, activeBatch: batchAfter(batch, res.problem.key) }, "bans", now, res.problem);
	await writeState(ctx, {
		...succeeded(measured, now),
		active: activeOf(res.value, now, res.value.length >= batch),
		activeBatch: batchGrown(batch, ACTIVE_BATCH),
	});
	return { step: "bans", ok: true, counted: 0 };
}

export function activeOf(
	alerts: Array<{ decisions?: Array<{ type?: string; duration?: string; value?: string }> | null }>,
	now: Date,
	truncated: boolean,
): ActiveSnapshot {
	const banned = new Set<string>();
	let decisions = 0;
	for (const alert of alerts) {
		for (const decision of alert.decisions ?? []) {
			const left = parseGoDuration(decision.duration);
			if (left === null || left <= 0) continue;
			decisions++;
			if ((decision.type ?? "").toLowerCase() === "ban" && decision.value) banned.add(decision.value);
		}
	}
	return { bans: banned.size, decisions, at: now.toISOString(), truncated };
}

/**
 * Look up the site's and the LAPI's addresses for the ban protections and
 * cache them. Calls: two requests per hostname and, when they answer, the
 * cache write.
 */
async function refreshDns(ctx: PluginContext, names: string[], now: Date): Promise<{ ok: boolean; requests: number }> {
	const http = ctx.http!;
	const res = await resolveNames((url, init) => http.fetch(url, init), names, now);
	if (!res.ok) return { ok: false, requests: res.requests };
	await ctx.kv.set(DNS_KEY, res.value);
	return { ok: true, requests: res.requests };
}

/** After a failed lookup, the next try waits this long. Bans stay refused meanwhile. */
const DNS_RETRY_MS = 6 * 3_600_000;

function retryAt(now: Date): string {
	return new Date(now.getTime() + DNS_RETRY_MS).toISOString();
}

/**
 * A tick that found the lease taken. A Refresh or a ban count asked for
 * by a person is scheduled again a minute later rather than lost.
 * Calls: the one schedule, at most.
 */
async function busy(ctx: PluginContext, mode: SyncMode, now: Date): Promise<SyncOutcome> {
	const task = mode === "refresh" ? REFRESH_TASK : mode === "bans" ? BANS_TASK : null;
	if (task && ctx.cron) await ctx.cron.schedule(task, { schedule: new Date(now.getTime() + 60_000).toISOString() });
	return { step: "busy", ok: true, counted: 0 };
}

/**
 * Clear the store after the dataset changed, in bounded batches: a query
 * and a delete per batch, six calls with the lease, the settings and the
 * state write around them. Until it is done, every tick resumes it.
 */
async function runWipe(ctx: PluginContext, state: SyncState, now: Date): Promise<SyncOutcome> {
	let calls = 6;
	let finished = true;
	for (const store of [alertsStore(ctx), daysStore(ctx)]) {
		if (!store) continue;
		let more = true;
		while (more && calls >= 2) {
			const page = await store.query({ limit: ID_BATCH });
			calls--;
			if (page.items.length > 0) {
				await store.deleteMany(page.items.map((item) => item.id));
				calls--;
			}
			more = page.hasMore || page.items.length === ID_BATCH;
		}
		if (more) {
			finished = false;
			break;
		}
	}
	// `dataset` stays until the store is empty, so the next tick resumes.
	await writeState(ctx, finished ? { lastSync: now.toISOString() } : state);
	return { step: "wipe", ok: true, counted: 0 };
}

/**
 * The daily prune: alert rows and day rows older than the retention.
 * Calls: settings.list, then a query and a delete per batch, four batches
 * shared by both collections (see AGENTS.md).
 */
export async function runReconcile(
	ctx: PluginContext,
	settings: Pick<CrowdSecSettings, "retentionDays" | "timeZone">,
	now: Date = new Date(),
): Promise<{ deleted: number; more: boolean }> {
	const cutoff = new Date(floorOf(settings, now));
	let deleted = 0;
	let more = false;
	let batches = 4;
	const passes: Array<[ReturnType<typeof alertsStore> | ReturnType<typeof daysStore>, Record<string, unknown>]> = [
		[alertsStore(ctx), { startedAt: { lt: cutoff.toISOString() } }],
		[daysStore(ctx), { date: { lt: localDay(cutoff, settings.timeZone) } }],
	];
	for (const [store, where] of passes) {
		if (!store) continue;
		let again = true;
		while (again && batches > 0) {
			batches--;
			const page = await store.query({ where, limit: ID_BATCH });
			if (page.items.length > 0) deleted += await store.deleteMany(page.items.map((item) => item.id));
			again = page.items.length === ID_BATCH;
		}
		if (again) more = true;
	}
	return { deleted, more };
}

function succeeded(state: SyncState, now: Date): SyncState {
	return { ...state, lastSync: now.toISOString(), lastError: undefined, lastProblem: undefined, lastErrorAt: undefined };
}

async function fail(ctx: PluginContext, state: SyncState, stepName: SyncOutcome["step"], now: Date, problem: Problem): Promise<SyncOutcome> {
	// The last good numbers stay. Stale and labelled beats blank.
	await writeState(ctx, { ...state, lastError: problem.key, lastProblem: problem, lastErrorAt: now.toISOString() });
	return { step: stepName, ok: false, counted: 0, problem };
}

/** The state revision each tick's lease claim wrote, so its last write can be made conditional on it. */
const revisions = new WeakMap<PluginContext, string>();

/**
 * Every write of the state releases the lease. A tick writes only over the
 * revision its own claim left: a tick that overran its lease, while another
 * claimed the state, has its write discarded instead of undoing the other's.
 * What it stored meanwhile is harmless, since rows are kept by id and counted once.
 */
async function writeState(ctx: PluginContext, state: SyncState): Promise<void> {
	const value = { ...state, lease: undefined };
	const revision = revisions.get(ctx);
	if (revision === undefined) {
		await ctx.kv.set(STATE_KEY, value);
		return;
	}
	const written = await ctx.kv.compareAndSet(STATE_KEY, revision, value);
	if (written.applied) revisions.set(ctx, written.revision);
}

/** The time from which stored alerts are complete up to `head`: the end of the newest gap, or the floor. */
export function coveredSince(state: SyncState): string | null {
	if (!state.head) return null;
	const gaps = state.gaps ?? [];
	return gaps.length > 0 ? gaps.reduce((max, gap) => (gap.to > max ? gap.to : max), gaps[0]!.to) : (state.floor ?? null);
}

/** Sum the hourly buckets that start in [since, until). */
export function sumHours(state: SyncState, since: number, until: number): HourBucket {
	const out: HourBucket = { alerts: 0, waf: 0, bot: 0, behaviour: 0, manual: 0, scenarios: {} };
	for (const [key, bucket] of Object.entries(state.hours ?? {})) {
		const start = hourStart(key);
		if (start < since || start >= until) continue;
		out.alerts += bucket.alerts;
		for (const kind of ["waf", "bot", "behaviour", "manual"] as Kind[]) out[kind] += bucket[kind];
		for (const [name, n] of Object.entries(bucket.scenarios)) out.scenarios[name] = (out.scenarios[name] ?? 0) + n;
	}
	return out;
}
