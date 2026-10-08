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
import type { RawAlert } from "../lapi/types.js";
import { displayNetwork, isSingleAddress, parseNetwork, sameNetwork } from "../net/ip.js";
import { readSettings, settingsOf } from "../settings.js";
import { buildSource } from "../sources.js";
import { compactAlert, KINDS, ranked, sumMaps, type Kind } from "../store/rows.js";
import { ACTIVE_BATCH, coveredSince, loadKv, sumHours, type ActiveSnapshot } from "../sync/scheduler.js";
import { readActive } from "../ui/decisions.js";
import { addDays, daysBetween, localDay, parseGoDuration, type Day } from "../sync/time.js";
import { loadDays } from "../ui/security.js";
import { decisionRows } from "../ui/decisions.js";
import { asRecord } from "../values.js";
import { addBan, deleteAlert, parseBanInput, removeBansOn, writeGate, type Caller } from "../write/actions.js";

export const TOOL_ROUTES = {
	summary: "mcp/security_summary",
	top: "mcp/top_threats",
	decisions: "mcp/active_decisions",
	ipAlerts: "mcp/ip_alerts",
	ban: "mcp/ban_ip",
	removeBan: "mcp/remove_ban",
	deleteAlert: "mcp/delete_alert",
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
	const res = await source.alerts({
		scope: isSingleAddress(network) ? "Ip" : "Range",
		value: address,
		limit: ADDRESS_ALERTS,
		simulated: result.settings.includeSimulated,
	});
	if (!res.ok) throw new Error(problemText("en", res.problem));
	return {
		address,
		truncated: res.value.length >= ADDRESS_ALERTS,
		alerts: res.value.flatMap((raw: RawAlert) => {
			if (!sameNetwork(raw.source?.value, address)) return [];
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

/** Delete one alert whose decisions ended more than two minutes ago. Calls: kv.list, settings.list, the GET, the DELETE, the row. */
export async function deleteAlertTool(ctx: PluginContext, routeCtx: Parameters<typeof callerOf>[0] & { input: unknown }): Promise<WriteToolResult> {
	const caller = callerOf(routeCtx);
	const wc = await writeContext(ctx, caller);
	if ("refused" in wc) return { done: false, message: wc.refused! };
	const res = await deleteAlert(ctx, wc.lapi, asRecord(routeCtx.input).id, WRITE_CALLS);
	if (!res.ok) return { done: false, message: problemText("en", res.problem) };
	return { done: true, message: problemText("en", { key: "alertDeleted", params: { id: res.value.id } }) };
}

/** The tool names the target `address`; the shared parser calls it `value`. */
function renameAddress(record: Record<string, unknown>): Record<string, unknown> {
	return { ...record, value: record.address };
}
