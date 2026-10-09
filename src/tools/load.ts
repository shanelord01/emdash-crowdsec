/**
 * The MCP tools' routes.
 *
 * Each call is one sandboxed route invocation with ten bridge calls. The
 * summary and the top lists answer from storage. Active decisions and an
 * address's alerts are read live from LAPI, as the Decisions page is.
 *
 * The input schemas in `./declare.ts` are build metadata: the build strips
 * them from the runtime and EmDash's MCP server validates a call against
 * them first. The same routes are reachable over HTTP without that, so
 * every handler reads its input by hand, and the write tools run every
 * check the admin pages run.
 */

import type { PluginContext } from "emdash/plugin";

import { problemText } from "../i18n.js";
import { isBlocklistAlert, isBlocklistDecision } from "../lapi/blocklist.js";
import type { RawAlert } from "../lapi/types.js";
import { displayNetwork, isSingleAddress, parseNetwork, sameNetwork } from "../net/ip.js";
import { readSettings, settingsOf } from "../settings.js";
import { buildSource } from "../sources.js";
import { compactAlert, KINDS, ranked, sumMaps, type Kind } from "../store/rows.js";
import { ACTIVE_BATCH, coveredSince, loadKv, metricsOn, sumHours, type ActiveSnapshot } from "../sync/scheduler.js";
import { readActive } from "../ui/decisions.js";
import { addDays, daysBetween, localDay, parseGoDuration, type Day } from "../sync/time.js";
import { loadDays, metricsFor, trafficFor } from "../ui/security.js";
import { discarded, sumCounters } from "../metrics/sample.js";
import { decisionRows } from "../ui/decisions.js";
import { asRecord } from "../values.js";
import { isBehaviour } from "../explorer/behaviour.js";
import { breakdown, bucketsOf, DEFAULT_VIEW, DIMENSIONS, groupByIp, rangeOf, select as selectAlerts, type Dim, type ExplorerView } from "../explorer/model.js";
import { loadExplorer } from "../ui/explorer.js";
import { addBan, deleteAlert, parseBanInput, removeBansOn, writeGate, type Caller } from "../write/actions.js";

export const TOOL_ROUTES = {
	summary: "mcp/security_summary",
	top: "mcp/top_threats",
	decisions: "mcp/active_decisions",
	ipAlerts: "mcp/ip_alerts",
	ban: "mcp/ban_ip",
	removeBan: "mcp/remove_ban",
	deleteAlert: "mcp/delete_alert",
	traffic: "mcp/traffic_summary",
	explorer: "mcp/alerts_explorer",
} as const;

export const RANGE_DAYS = [7, 30, 90] as const;
export const DEFAULT_DAYS = 30;
export const DEFAULT_TOP = 10;
export const MAX_TOP = 25;
export const DEFAULT_DECISIONS = 50;
export const MAX_DECISIONS = 100;
export const ADDRESS_ALERTS = 50;
/** Bridge calls a write tool may spend on LAPI: ten, less kv.list and settings.list. */
const WRITE_CALLS = 8;

const HOUR_MS = 3_600_000;

export interface ToolWindow {
	days: number;
	since: Day;
	until: Day;
	/** True when stored history starts after `since`. */
	partial: boolean;
}

type KindCounts = Record<Kind, number>;

export interface SummaryResult {
	window: ToolWindow;
	alerts: number;
	byKind: KindCounts;
	decisions: number;
	bans: number;
	previous: { alerts: number; bans: number } | null;
	last24Hours: { alerts: number; byKind: KindCounts; previous24Hours: number | null };
	activeBans: ActiveSnapshot | null;
	lastSync: string | null;
}

export interface TopResult {
	window: ToolWindow;
	scenarios: Array<{ value: string; alerts: number }>;
	sources: Array<{ value: string; alerts: number }>;
	countries: Array<{ value: string; alerts: number }>;
	asNames: Array<{ value: string; alerts: number }>;
	paths: Array<{ value: string; alerts: number }>;
	lastSync: string | null;
}

export interface DecisionsResult {
	readAt: string;
	total: number;
	truncated: boolean;
	communityBlocklist: { addresses: number | null; at: string } | null;
	decisions: Array<{
		id: number;
		value: string;
		scenario: string;
		type: string;
		origin: string;
		remainingSeconds: number;
		expiresAt: string;
		country: string;
		asName: string;
	}>;
}

export interface AddressAlertsResult {
	address: string;
	truncated: boolean;
	communityBlocklist: Array<{ id: number; origin: string; scenario: string; type: string; remainingSeconds: number }>;
	alerts: Array<{
		id: number;
		startedAt: string;
		kind: Kind;
		scenario: string;
		country: string;
		asName: string;
		path: string;
		decisions: Array<{ id: number; type: string; remainingSeconds: number }>;
	}>;
}

type OriginCounts = { community: number; detections: number; manual: number; other: number };

export interface TrafficResult {
	window: ToolWindow;
	/** False when no metrics URL is set and the data is not demo data. */
	enabled: boolean;
	sampledSince: string | null;
	discarded: { packets: number; bytes: number; packetsByOrigin: OriginCounts; bytesByOrigin: OriginCounts };
	processedPackets: number;
	/** Discarded packets as a share of the packets the bouncer checked, 0 to 1, or null when it checked none. */
	share: number | null;
	appsec: { inspected: number; blocked: number };
	challenge: { requested: number; submitted: number; accepted: number; rejected: number; exempt: number };
	activeByOrigin: OriginCounts | null;
}

export const EXPLORER_PERIODS = ["1h", "24h", "3d", "7d", "30d", "all"] as const;
export const MAX_GROUPS = 50;

export interface ExplorerBreakdown {
	dimension: Dim;
	total: number;
	top: Array<{ value: string; alerts: number; share: number }>;
	other: number;
}

export interface ExplorerResult {
	period: { name: (typeof EXPLORER_PERIODS)[number]; since: string; until: string };
	total: number;
	partial: boolean;
	breakdowns: ExplorerBreakdown[];
	groups: {
		total: number;
		nextPage: number | null;
		items: Array<{
			address: string;
			country: string;
			asName: string;
			alerts: number;
			firstSeen: string;
			lastSeen: string;
			wafAlerts: number;
			scenarios: Array<{ value: string; alerts: number }>;
			paths: Array<{ value: string; alerts: number }>;
			decisions: number;
			bannedUntil: string | null;
			seenBefore: boolean;
			engines: Array<{ id: string; name: string }>;
		}>;
	};
	lastSync: string | null;
}

export interface WriteToolResult {
	done: boolean;
	message: string;
	value?: string;
	alertId?: string;
	clientAddressChecked?: boolean;
	removed?: number;
	remaining?: number;
}

function pickDays(value: unknown): (typeof RANGE_DAYS)[number] {
	const n = typeof value === "string" ? Number(value) : value;
	return (RANGE_DAYS as readonly unknown[]).includes(n) ? (n as (typeof RANGE_DAYS)[number]) : DEFAULT_DAYS;
}

function limitOf(value: unknown, fallback: number, max: number): number {
	const n = typeof value === "string" ? Number(value) : value;
	if (typeof n !== "number" || !Number.isInteger(n) || n < 1) return fallback;
	return Math.min(n, max);
}

function windowOf(days: number, today: Day, covered: string | null, zone: string): ToolWindow {
	const since = addDays(today, -(days - 1));
	return { days, since, until: today, partial: covered === null || daysBetween(since, localDay(covered, zone)) > 0 };
}

function zeroKinds(): KindCounts {
	return { waf: 0, bot: 0, behaviour: 0, manual: 0 };
}

/** Alerts, bans and kinds over 7, 30 or 90 days with the period before, and the last 24 hours. Calls: kv.list, settings.list and two day queries. */
export async function securitySummary(ctx: PluginContext, input: unknown, now: Date): Promise<SummaryResult> {
	const days = pickDays(asRecord(input).days);
	const { state } = await loadKv(ctx);
	const zone = settingsOf(await readSettings(ctx)).timeZone;
	const today = localDay(now, zone);
	const covered = coveredSince(state);
	const window = windowOf(days, today, covered, zone);
	const previousSince = addDays(today, -(days * 2 - 1));
	const rows = await loadDays(ctx, previousSince);
	const inRange = rows.filter((row) => row.date >= window.since);
	const before = rows.filter((row) => row.date < window.since);

	const byKind = zeroKinds();
	for (const row of inRange) for (const kind of KINDS) byKind[kind] += row[kind];
	const sum = (list: typeof rows, key: "alerts" | "bans" | "decisions") => list.reduce((n, row) => n + row[key], 0);
	const hasPrevious = covered !== null && localDay(covered, zone) <= previousSince;

	const nowMs = now.getTime();
	const last = sumHours(state, nowMs - 24 * HOUR_MS, nowMs + HOUR_MS);
	const prior = sumHours(state, nowMs - 48 * HOUR_MS, nowMs - 24 * HOUR_MS);
	const has48 = covered !== null && Date.parse(covered) <= nowMs - 48 * HOUR_MS;

	return {
		window,
		alerts: sum(inRange, "alerts"),
		byKind,
		decisions: sum(inRange, "decisions"),
		bans: sum(inRange, "bans"),
		previous: hasPrevious ? { alerts: sum(before, "alerts"), bans: sum(before, "bans") } : null,
		last24Hours: {
			alerts: last.alerts,
			byKind: { waf: last.waf, bot: last.bot, behaviour: last.behaviour, manual: last.manual },
			previous24Hours: has48 ? prior.alerts : null,
		},
		activeBans: state.active ?? null,
		lastSync: state.lastSync ?? null,
	};
}

/** The most frequent scenarios, source addresses, countries, AS organisations and paths. Calls: kv.list, settings.list and one day query. */
export async function topThreats(ctx: PluginContext, input: unknown, now: Date): Promise<TopResult> {
	const record = asRecord(input);
	const days = pickDays(record.days);
	const limit = limitOf(record.limit, DEFAULT_TOP, MAX_TOP);
	const { state } = await loadKv(ctx);
	const zone = settingsOf(await readSettings(ctx)).timeZone;
	const today = localDay(now, zone);
	const window = windowOf(days, today, coveredSince(state), zone);
	const rows = await loadDays(ctx, window.since);
	const top = (pick: (row: (typeof rows)[number]) => Record<string, number>) =>
		ranked(sumMaps(rows.map(pick)))
			.slice(0, limit)
			.map(([value, alerts]) => ({ value, alerts }));
	return {
		window,
		scenarios: top((row) => row.scenarios),
		sources: top((row) => row.ips),
		countries: top((row) => row.countries),
		asNames: top((row) => row.asNames),
		paths: top((row) => row.paths),
		lastSync: state.lastSync ?? null,
	};
}

/**
 * Malicious traffic discarded and web requests over 7, 30 or 90 days, from
 * the stored traffic days the metrics sampler fills.
 * Calls: kv.list, settings.list, one or two traffic queries.
 */
export async function trafficSummary(ctx: PluginContext, input: unknown, now: Date): Promise<TrafficResult> {
	const days = pickDays(asRecord(input).days);
	const loaded = await loadKv(ctx);
	const settings = settingsOf(await readSettings(ctx));
	const zone = settings.timeZone;
	const today = localDay(now, zone);
	const since = addDays(today, -(days - 1));
	const metrics = metricsFor(loaded.metrics, settings, now);
	const window: ToolWindow = { days, since, until: today, partial: !metrics || localDay(metrics.since, zone) > since };
	const rows = metricsOn(settings) ? await trafficFor(ctx, settings, since, now) : [];
	const c = sumCounters(rows.filter((r) => r.date <= today).map((r) => r.counters));
	const packets = discarded(c, "packets");
	const bytes = discarded(c, "bytes");
	const strip = (d: OriginCounts & { total: number }): OriginCounts => ({ community: d.community, detections: d.detections, manual: d.manual, other: d.other });
	const processed = c["proc.packets"] ?? 0;
	return {
		window,
		enabled: metricsOn(settings),
		sampledSince: metrics?.since ?? null,
		discarded: { packets: packets.total, bytes: bytes.total, packetsByOrigin: strip(packets), bytesByOrigin: strip(bytes) },
		processedPackets: processed,
		share: processed > 0 ? Math.round((Math.min(1, packets.total / processed)) * 10_000) / 10_000 : null,
		appsec: { inspected: c["as.reqs"] ?? 0, blocked: c["as.blocks"] ?? 0 },
		challenge: {
			requested: c["ch.requested"] ?? 0,
			submitted: c["ch.submitted"] ?? 0,
			accepted: c["ch.accepted"] ?? 0,
			rejected: c["ch.rejected"] ?? 0,
			exempt: c["ch.exempt"] ?? 0,
		},
		activeByOrigin: metrics?.gauges ? { ...metrics.gauges.bansByOrigin } : null,
	};
}

/** The active decisions, read live. Calls: kv.list, settings.list, the login and up to three searches, each half the last after an answer over 8 MiB. */
export async function activeDecisions(ctx: PluginContext, input: unknown, now: Date): Promise<DecisionsResult> {
	const limit = limitOf(asRecord(input).limit, DEFAULT_DECISIONS, MAX_DECISIONS);
	const loaded = await loadKv(ctx);
	const result = await readSettings(ctx);
	if (!result.ok) throw new Error(problemText("en", result.problem));
	const source = buildSource(ctx, result.settings, loaded.state.skewMs);
	if (!source) throw new Error(problemText("en", { key: "noNetwork" }));
	const res = await readActive(source, result.settings, loaded.state.activeBatch ?? ACTIVE_BATCH);
	if (!res.ok) throw new Error(problemText("en", res.problem));
	const rows = decisionRows(res.value.alerts, now).sort((a, b) => a.remaining - b.remaining || a.id - b.id);
	return {
		readAt: now.toISOString(),
		total: rows.length,
		truncated: res.value.truncated || rows.length > limit,
		communityBlocklist: loaded.blocklist ? { addresses: loaded.blocklist.addresses, at: loaded.blocklist.at } : null,
		decisions: rows.slice(0, limit).map((row) => ({
			id: row.id,
			value: row.value,
			scenario: row.scenario,
			type: row.type,
			origin: row.origin,
			remainingSeconds: Math.round(row.remaining),
			expiresAt: row.expires,
			country: row.country,
			asName: row.asName,
		})),
	};
}

/**
 * The alerts LAPI holds for one address or range, read live by `scope` and
 * `value`, keeping only those whose source is exactly that address or
 * range. Never with `ip=`, which also matches alerts with an empty source.
 * Calls: kv.list, settings.list, the search with its login and retry.
 */
export async function addressAlerts(ctx: PluginContext, input: unknown, now: Date): Promise<AddressAlertsResult> {
	const parsed = parseNetwork(asRecord(input).address);
	if (!parsed) throw new Error(problemText("en", { key: "invalidAddress" }));
	// LAPI stores an IPv4 address in IPv4 form, so `::ffff:a.b.c.d` is searched as `a.b.c.d`.
	const address = displayNetwork(parsed);
	const network = parseNetwork(address)!;
	const loaded = await loadKv(ctx);
	const result = await readSettings(ctx);
	if (!result.ok) throw new Error(problemText("en", result.problem));
	const source = buildSource(ctx, result.settings, loaded.state.skewMs);
	if (!source) throw new Error(problemText("en", { key: "noNetwork" }));
	// One address's search includes the community blocklist and lists, so
	// the answer can say the address is on one. Their alerts are not listed.
	const res = await source.alerts({
		scope: isSingleAddress(network) ? "Ip" : "Range",
		value: address,
		limit: ADDRESS_ALERTS,
		simulated: result.settings.includeSimulated,
		blocklists: "include",
	});
	if (!res.ok) throw new Error(problemText("en", res.problem));
	const blocklist = res.value.flatMap((raw) =>
		(raw.decisions ?? []).flatMap((d) => {
			const left = parseGoDuration(d.duration);
			if (!isBlocklistDecision(d) || typeof d.id !== "number" || !sameNetwork(d.value, address) || left === null || left <= 0) return [];
			return [{ id: d.id, origin: d.origin ?? "", scenario: d.scenario ?? "", type: d.type ?? "", remainingSeconds: Math.round(left) }];
		}),
	);
	return {
		address,
		truncated: res.value.length >= ADDRESS_ALERTS,
		communityBlocklist: blocklist,
		alerts: res.value.flatMap((raw: RawAlert) => {
			if (isBlocklistAlert(raw) || !sameNetwork(raw.source?.value, address)) return [];
			const row = compactAlert(raw, now, result.settings.timeZone);
			if (!row) return [];
			return [
				{
					id: row.id,
					startedAt: row.startedAt,
					kind: row.kind,
					scenario: row.scenario,
					country: row.country,
					asName: row.asName,
					path: row.path,
					decisions: (raw.decisions ?? []).flatMap((d) =>
						typeof d.id === "number" ? [{ id: d.id, type: d.type ?? "", remainingSeconds: Math.round(parseGoDuration(d.duration) ?? 0) }] : [],
					),
				},
			];
		}),
	};
}

function callerOf(routeCtx: { user?: Caller["user"]; requestMeta?: unknown; request?: { headers?: Record<string, string> } }): Caller {
	return { user: routeCtx.user ?? null, requestMeta: routeCtx.requestMeta, request: routeCtx.request, channel: "mcp" };
}

/** Shared start of every write tool: settings, the gate, the LAPI client. Calls: kv.list, settings.list. */
async function writeContext(ctx: PluginContext, caller: Caller) {
	const loaded = await loadKv(ctx);
	const result = await readSettings(ctx);
	const settings = settingsOf(result);
	// The route's `plugins:manage` was enforced by the host, so no role check here.
	const gate = writeGate(settings, caller, false);
	if (!gate.ok) return { refused: problemText("en", gate.problem) } as const;
	if (!result.ok) return { refused: problemText("en", result.problem) } as const;
	const source = buildSource(ctx, settings, loaded.state.skewMs);
	if (!source?.lapi) return { refused: problemText("en", { key: "noNetwork" }) } as const;
	return { loaded, settings, lapi: source.lapi } as const;
}

/** Add a ban or captcha. Calls: kv.list, settings.list, then the checks, the allowlist check and the POST: ten at most. */
export async function banAddressTool(ctx: PluginContext, routeCtx: Parameters<typeof callerOf>[0] & { input: unknown }, now: Date): Promise<WriteToolResult> {
	const caller = callerOf(routeCtx);
	const parsed = parseBanInput(renameAddress(asRecord(routeCtx.input)));
	if (!parsed.ok) return { done: false, message: problemText("en", parsed.problem) };
	const wc = await writeContext(ctx, caller);
	if ("refused" in wc) return { done: false, message: wc.refused! };
	const res = await addBan(ctx, wc.lapi, wc.settings, wc.loaded.dns, caller, parsed.value, now);
	if (!res.ok) return { done: false, message: problemText("en", res.problem) };
	const message = problemText("en", {
		key: res.value.ownChecked ? "banDone" : "banDoneUncheckedMcp",
		params: { type: res.value.type, value: res.value.value, duration: res.value.duration },
	});
	return { done: true, message, value: res.value.value, alertId: res.value.alertId, clientAddressChecked: res.value.ownChecked };
}

/** Remove the active decisions on one address or range. Calls: kv.list, settings.list, the search and the deletes that fit. */
export async function removeBanTool(ctx: PluginContext, routeCtx: Parameters<typeof callerOf>[0] & { input: unknown }): Promise<WriteToolResult> {
	const caller = callerOf(routeCtx);
	const wc = await writeContext(ctx, caller);
	if ("refused" in wc) return { done: false, message: wc.refused! };
	const res = await removeBansOn(wc.lapi, asRecord(routeCtx.input).address, WRITE_CALLS);
	if (!res.ok) return { done: false, message: problemText("en", res.problem) };
	const message = problemText("en", {
		key: res.value.remaining > 0 ? "removedSome" : "removedAll",
		params: { count: res.value.removed, remaining: res.value.remaining, value: res.value.value },
	});
	return { done: res.value.removed > 0, message, value: res.value.value, removed: res.value.removed, remaining: res.value.remaining };
}

/**
 * The Alerts explorer's numbers for an agent: one period's stored alerts,
 * of one kind and matching every filter given, broken down by up to two
 * dimensions, and grouped by source address. The same working as the page,
 * from the same alert log. Calls: kv.list, settings.list, the day rows
 * before the period and up to four log queries.
 */
export async function alertsExplorer(ctx: PluginContext, input: unknown, now: Date): Promise<ExplorerResult> {
	const raw = asRecord(input);
	const name = (EXPLORER_PERIODS as readonly unknown[]).includes(raw.period) ? (raw.period as (typeof EXPLORER_PERIODS)[number]) : "24h";
	const kind = (KINDS as readonly unknown[]).includes(raw.kind) ? (raw.kind as Kind) : null;
	const text = (v: unknown) => (typeof v === "string" && v.trim() && v.trim().length <= 200 ? v.trim() : undefined);
	const address = text(raw.address);
	if (address && !parseNetwork(address)) throw new Error(problemText("en", { key: "invalidAddress" }));
	const behaviour = text(raw.behaviour);
	const f = {
		...(address && { ip: address }),
		...(text(raw.country) && { cn: text(raw.country)!.toUpperCase() }),
		...(text(raw.scenario) && { sc: text(raw.scenario) }),
		...(behaviour && isBehaviour(behaviour) && { bh: behaviour }),
		...(text(raw.asName) && { as: text(raw.asName) }),
		...(text(raw.path) && { tg: text(raw.path) }),
		...(text(raw.engine) && { en: text(raw.engine) }),
	};
	const dims = (Array.isArray(raw.breakdowns) ? raw.breakdowns : ["ip", "behaviour"]).filter((d): d is Dim => (DIMENSIONS as readonly unknown[]).includes(d)).slice(0, 2);
	const limit = Number.isInteger(raw.limit) && (raw.limit as number) >= 1 ? Math.min(MAX_GROUPS, raw.limit as number) : 20;
	const page = Number.isInteger(raw.page) && (raw.page as number) > 0 ? Math.min(10_000, raw.page as number) : 0;

	const loaded = await loadKv(ctx);
	const settings = settingsOf(await readSettings(ctx));
	const zone = settings.timeZone;
	// Paging keeps the end the first page answered with, so no address is dropped or repeated.
	const until = typeof raw.until === "string" ? Date.parse(raw.until) : Number.NaN;
	const view: ExplorerView = { ...DEFAULT_VIEW, p: name === "all" ? "ret" : name, k: kind, f, ...(Number.isFinite(until) && until > 0 && { at: until }) };
	const range = rangeOf(view, now, zone, settings.retentionDays, null);
	const data = await loadExplorer(ctx, range, zone, 5);
	const selected = selectAlerts(data.period, view, range);
	const buckets = bucketsOf(range, zone);
	const groups = groupByIp(selected, now);
	const iso = (ms: number) => new Date(ms).toISOString();
	const top = (list: Array<[string, number]>) => list.slice(0, 5).map(([value, alerts]) => ({ value, alerts }));
	return {
		period: { name, since: iso(range.since), until: iso(range.until) },
		total: selected.length,
		partial: data.partial,
		breakdowns: dims.map((dimension) => {
			const b = breakdown(selected, dimension, buckets, 5);
			return { dimension, total: b.total, top: b.top.map((t) => ({ ...t, share: Math.round(t.share * 10_000) / 10_000 })), other: b.other };
		}),
		groups: {
			total: groups.length,
			nextPage: (page + 1) * limit < groups.length ? page + 1 : null,
			items: groups.slice(page * limit, (page + 1) * limit).map((g) => ({
				address: g.ip,
				country: g.country,
				asName: g.asName,
				alerts: g.alerts,
				firstSeen: iso(g.first),
				lastSeen: iso(g.last),
				wafAlerts: g.waf,
				scenarios: top(g.scenarios),
				paths: top(g.paths),
				decisions: g.decisions,
				bannedUntil: g.bannedUntil ? iso(g.bannedUntil) : null,
				seenBefore: data.seenBefore.has(g.ip),
				engines: g.engines.map((id) => ({ id, name: settings.engineNames[id] ?? id })),
			})),
		},
		lastSync: loaded.state.lastSync ?? null,
	};
}

/** Delete one alert whose decisions ended more than two minutes ago. Calls: kv.list, settings.list, the login, the GET, the DELETE, the log's query and write. */
export async function deleteAlertTool(ctx: PluginContext, routeCtx: Parameters<typeof callerOf>[0] & { input: unknown }): Promise<WriteToolResult> {
	const caller = callerOf(routeCtx);
	const wc = await writeContext(ctx, caller);
	if ("refused" in wc) return { done: false, message: wc.refused! };
	const res = await deleteAlert(ctx, wc.lapi, asRecord(routeCtx.input).id, wc.settings.timeZone, WRITE_CALLS);
	if (!res.ok) return { done: false, message: problemText("en", res.problem) };
	return { done: true, message: problemText("en", { key: "alertDeleted", params: { id: res.value.id } }) };
}

/** The tool names the target `address`; the shared parser calls it `value`. */
function renameAddress(record: Record<string, unknown>): Record<string, unknown> {
	return { ...record, value: record.address };
}
