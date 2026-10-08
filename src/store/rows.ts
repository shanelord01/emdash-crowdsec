/**
 * Stored rows and how a LAPI alert becomes one. Pure.
 *
 * An alert in LAPI's JSON averages about 13 KB, almost all of it in
 * `events`. The plugin keeps a row of a few hundred bytes: what the
 * Alerts page shows and the MCP tools answer with. Charts and top lists
 * read per-day totals instead (`DayRow`), so no page ever reads a month of
 * alert rows.
 */

import type { RawAlert, RawMeta } from "../lapi/types.js";
import { localDay, parseGoDuration, type Day } from "../sync/time.js";

export const KINDS = ["waf", "bot", "behaviour", "manual"] as const;
export type Kind = (typeof KINDS)[number];

/** One alert. `id` is LAPI's alert id as a string. */
export interface AlertRow {
	id: number;
	/** When the alert's first event happened, ISO 8601. LAPI's `since` and `until` search on this. */
	startedAt: string;
	createdAt: string;
	day: Day;
	kind: Kind;
	scenario: string;
	/** The source address, or the range for a range alert. */
	ip: string;
	scope: string;
	country: string;
	asName: string;
	/** The first path the source requested, when the alert says. */
	path: string;
	host: string;
	events: number;
	simulated: boolean;
	/** Decisions the alert carried when it was read, and how many were bans. */
	decisions: number;
	bans: number;
	/** The first decision's type, empty without one. */
	decisionType: string;
	/** When the alert's last decision ends, ISO 8601, as read. */
	decisionUntil?: string;
}

/**
 * One local day's totals, in the Time zone setting. `id` is the date.
 *
 * `seen` holds the alert ids already counted into the day, as sorted
 * inclusive ranges. Windows overlap at their edges on purpose, and a tick
 * may die between its writes, so counting checks it: an alert is added to
 * a day once, whichever window brings it.
 */
export interface DayRow {
	date: Day;
	alerts: number;
	waf: number;
	bot: number;
	behaviour: number;
	manual: number;
	/** Decisions issued with the day's alerts, and the bans among them. */
	decisions: number;
	bans: number;
	scenarios: Record<string, number>;
	countries: Record<string, number>;
	asNames: Record<string, number>;
	paths: Record<string, number>;
	ips: Record<string, number>;
	seen: Array<[number, number]>;
	updatedAt: string;
}

/** Values kept per top list per day. Lower counts fall off the end. */
export const DAY_TOP_KEEP = 25;

const MAX_TEXT = 200;

export function emptyDay(date: Day, now: Date): DayRow {
	return {
		date,
		alerts: 0,
		waf: 0,
		bot: 0,
		behaviour: 0,
		manual: 0,
		decisions: 0,
		bans: 0,
		scenarios: {},
		countries: {},
		asNames: {},
		paths: {},
		ips: {},
		seen: [],
		updatedAt: now.toISOString(),
	};
}

/**
 * Which of the dashboard's groups an alert belongs to.
 *
 * LAPI's `kind` is `waf` for AppSec rules and virtual patches, `manual` for
 * a ban added by hand and `crowdsec` for log scenarios. The AppSec bot
 * challenge reports as `bot-detection`, and its scenarios
 * (`appsec-bot-challenge-*`) report as `crowdsec`, so the scenario name
 * decides those.
 */
export function kindOf(alert: Pick<RawAlert, "kind" | "scenario">): Kind {
	const kind = (alert.kind ?? "").toLowerCase();
	const scenario = (alert.scenario ?? "").toLowerCase();
	if (kind === "waf" || kind === "appsec") return "waf";
	if (kind === "manual" || scenario.startsWith("manual '")) return "manual";
	if (kind === "bot-detection" || scenario.includes("bot-challenge") || scenario.includes("bot-detection")) return "bot";
	return "behaviour";
}

/** A LAPI alert as a stored row, or null when it has no id or start time. `day` is the local day in `zone`. */
export function compactAlert(raw: RawAlert, fetchedAt: Date, zone: string): AlertRow | null {
	if (typeof raw.id !== "number" || !Number.isFinite(raw.id)) return null;
	const started = Date.parse(raw.start_at ?? raw.created_at ?? "");
	if (Number.isNaN(started)) return null;
	const created = Date.parse(raw.created_at ?? "");
	const source = raw.source ?? {};
	const decisions = Array.isArray(raw.decisions) ? raw.decisions : [];

	let until: number | undefined;
	for (const decision of decisions) {
		const left = parseGoDuration(decision.duration);
		if (left === null) continue;
		const end = fetchedAt.getTime() + left * 1000;
		if (until === undefined || end > until) until = end;
	}

	return {
		id: raw.id,
		startedAt: new Date(started).toISOString(),
		createdAt: new Date(Number.isNaN(created) ? started : created).toISOString(),
		day: localDay(started, zone),
		kind: kindOf(raw),
		scenario: text(raw.scenario),
		ip: text(source.value ?? source.ip ?? source.range),
		scope: text(source.scope),
		country: text(source.cn).toUpperCase(),
		asName: text(source.as_name),
		path: pathOf(raw),
		host: hostOf(raw),
		events: typeof raw.events_count === "number" ? raw.events_count : 0,
		simulated: raw.simulated === true,
		decisions: decisions.length,
		bans: decisions.filter((d) => (d.type ?? "").toLowerCase() === "ban").length,
		decisionType: text(decisions[0]?.type),
		...(until !== undefined && { decisionUntil: new Date(until).toISOString() }),
	};
}

function text(value: unknown): string {
	return typeof value === "string" ? value.trim().slice(0, MAX_TEXT) : "";
}

function metaValue(meta: RawMeta[] | null | undefined, ...keys: string[]): string | undefined {
	for (const key of keys) {
		const found = meta?.find((entry) => entry.key === key)?.value;
		if (typeof found === "string" && found) return found;
	}
	return undefined;
}

/**
 * The first targeted path. Alert-level meta holds JSON-encoded arrays
 * (`["/a","/b"]`), and event meta holds plain strings. The query string is
 * dropped, so `/x?id=1` and `/x?id=2` count as one path.
 */
export function pathOf(raw: RawAlert): string {
	let value = metaValue(raw.meta, "target_uri");
	if (value) {
		try {
			const list = JSON.parse(value) as unknown;
			value = Array.isArray(list) && typeof list[0] === "string" ? list[0] : value;
		} catch {
			// A plain string, kept as it is.
		}
	}
	value ??= metaValue(raw.events?.[0]?.meta, "target_uri", "uri", "http_path");
	return text((value ?? "").split("?")[0]);
}

function hostOf(raw: RawAlert): string {
	return text(metaValue(raw.events?.[0]?.meta, "target_host", "target_fqdn")).toLowerCase();
}

/** Is `id` inside one of the sorted ranges? */
export function seenHas(seen: Array<[number, number]>, id: number): boolean {
	let lo = 0;
	let hi = seen.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		const [start, end] = seen[mid]!;
		if (id < start) hi = mid - 1;
		else if (id > end) lo = mid + 1;
		else return true;
	}
	return false;
}

/** Add `id` to the sorted ranges, joining neighbours. */
export function seenAdd(seen: Array<[number, number]>, id: number): Array<[number, number]> {
	if (seenHas(seen, id)) return seen;
	const out = [...seen.map((range) => [...range] as [number, number]), [id, id] as [number, number]].sort(
		(a, b) => a[0] - b[0],
	);
	const merged: Array<[number, number]> = [];
	for (const range of out) {
		const last = merged[merged.length - 1];
		if (last && range[0] <= last[1] + 1) last[1] = Math.max(last[1], range[1]);
		else merged.push(range);
	}
	return merged;
}

/**
 * Most id ranges one day row keeps. A row holds only the ids of alerts that
 * started on its own day, and adjacent ids join into one range, so a day
 * normally needs a handful. Ids of alerts that started on other days, or
 * that the sync leaves out, cut the ranges up. Past this many, the two
 * ranges closest together are joined: an alert whose id fell in that hole
 * and that has not been read yet would then not be counted. Counting too
 * few is the safe direction, counting twice is not.
 */
export const MAX_SEEN_RANGES = 200;

/** Join the closest ranges until at most `max` are left. */
export function compactSeen(seen: Array<[number, number]>, max = MAX_SEEN_RANGES): Array<[number, number]> {
	const out = seen.map((range) => [...range] as [number, number]);
	while (out.length > max) {
		let best = 0;
		for (let i = 1; i < out.length - 1; i++) {
			if (out[i + 1]![0] - out[i]![1] < out[best + 1]![0] - out[best]![1]) best = i;
		}
		out.splice(best, 2, [out[best]![0], out[best + 1]![1]]);
	}
	return out;
}

/** Count one alert into its own day. Returns false when the day had counted it already, or the alert is another day's. */
export function countInto(day: DayRow, alert: AlertRow): boolean {
	if (alert.day !== day.date) return false;
	if (seenHas(day.seen, alert.id)) return false;
	day.seen = compactSeen(seenAdd(day.seen, alert.id));
	day.alerts++;
	day[alert.kind]++;
	day.decisions += alert.decisions;
	day.bans += alert.bans;
	bump(day.scenarios, alert.scenario);
	bump(day.countries, alert.country);
	bump(day.asNames, alert.asName);
	bump(day.paths, alert.path);
	bump(day.ips, alert.ip);
	return true;
}

function bump(map: Record<string, number>, key: string): void {
	if (!key) return;
	map[key] = (map[key] ?? 0) + 1;
}

/** Keep each top list of a day to its `DAY_TOP_KEEP` largest values. */
export function trimDay(day: DayRow): DayRow {
	return {
		...day,
		scenarios: topOf(day.scenarios, DAY_TOP_KEEP),
		countries: topOf(day.countries, DAY_TOP_KEEP),
		asNames: topOf(day.asNames, DAY_TOP_KEEP),
		paths: topOf(day.paths, DAY_TOP_KEEP),
		ips: topOf(day.ips, DAY_TOP_KEEP),
	};
}

export function topOf(map: Record<string, number>, keep: number): Record<string, number> {
	return Object.fromEntries(ranked(map).slice(0, keep));
}

/** Entries by count, largest first, ties by name. */
export function ranked(map: Record<string, number>): Array<[string, number]> {
	return Object.entries(map).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** Sum maps of counts. */
export function sumMaps(maps: Array<Record<string, number>>): Record<string, number> {
	const out: Record<string, number> = {};
	for (const map of maps) for (const [key, n] of Object.entries(map)) out[key] = (out[key] ?? 0) + n;
	return out;
}
