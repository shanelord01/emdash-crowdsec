/**
 * The Alerts explorer's working: periods, filters, breakdowns, histograms
 * and groups by address. Pure, so the page and the `alerts_explorer` tool
 * work out the same numbers from the same alerts.
 *
 * Block Kit keeps no state between interactions. The whole view (period,
 * step back, kind, filters, the two breakdowns, grouping, table page, the
 * address and the alert being looked at) travels in each control's action
 * id, after a `|`, as a short query string.
 */

import { isBlocklistScope } from "../lapi/blocklist.js";
import { kindOfLog, type LogAlert } from "../store/log.js";
import { KINDS, type Kind } from "../store/rows.js";
import { addDays, dayStart, localDay, type Day } from "../sync/time.js";
import { contains, parseNetwork } from "../net/ip.js";
import { behaviourOf, isBehaviour, type Behaviour } from "./behaviour.js";

export const DIMENSIONS = ["ip", "behaviour", "country", "as", "scenario", "path", "kind", "engine"] as const;
export type Dim = (typeof DIMENSIONS)[number];

export const PERIODS = ["1h", "24h", "3d", "7d", "30d", "ret", "visit"] as const;
export type PeriodKey = (typeof PERIODS)[number];

export interface Filters {
	/** An address or a CIDR range. */
	ip?: string;
	cn?: string;
	sc?: string;
	bh?: Behaviour;
	as?: string;
	tg?: string;
	/** The CrowdSec agent's `machine_id`. */
	en?: string;
}

export const FILTER_KEYS = ["ip", "cn", "sc", "bh", "as", "tg", "en"] as const;
export type FilterKey = (typeof FILTER_KEYS)[number];

export interface ExplorerView {
	p: PeriodKey;
	/** Periods stepped back from now. */
	o: number;
	k: Kind | null;
	f: Filters;
	b: [Dim, Dim];
	/** True for groups by address, false for each alert. */
	g: boolean;
	/** Table page. */
	n: number;
	/** The address being looked at. */
	d?: string;
	/** The alert being looked at. */
	al?: number;
	/** The instant a rolling period ends at, epoch milliseconds: set on the first page, so paging reads the same period. */
	at?: number;
}

export const DEFAULT_VIEW: ExplorerView = { p: "24h", o: 0, k: null, f: {}, b: ["ip", "behaviour"], g: true, n: 0 };

const KIND_CODE: Record<Kind, string> = { waf: "w", bot: "b", behaviour: "h", manual: "m" };
const CODE_KIND: Record<string, Kind> = { w: "waf", b: "bot", h: "behaviour", m: "manual" };
/** As long as a stored value may be (`src/store/rows.ts`), so any value shown can be a filter. */
const MAX_TEXT = 200;

export function encodeView(view: ExplorerView): string {
	const parts: string[] = [`p=${view.p}`];
	if (view.o) parts.push(`o=${view.o}`);
	if (view.k) parts.push(`k=${KIND_CODE[view.k]}`);
	parts.push(`b=${view.b[0]}.${view.b[1]}`);
	if (!view.g) parts.push("g=0");
	if (view.n) parts.push(`n=${view.n}`);
	for (const key of FILTER_KEYS) {
		const value = view.f[key];
		if (value) parts.push(`${key}=${encodeURIComponent(value)}`);
	}
	if (view.d) parts.push(`d=${encodeURIComponent(view.d)}`);
	if (view.al) parts.push(`al=${view.al}`);
	if (view.at) parts.push(`at=${view.at}`);
	return parts.join("&");
}

function text(value: string | undefined): string | undefined {
	if (!value) return undefined;
	try {
		const decoded = decodeURIComponent(value).trim();
		return decoded && decoded.length <= MAX_TEXT ? decoded : undefined;
	} catch {
		return undefined;
	}
}

/** A view from its encoded form. Anything unknown falls back to the default, never to an error. */
export function decodeView(encoded: string): ExplorerView {
	const map = new Map<string, string>();
	for (const pair of encoded.split("&")) {
		const cut = pair.indexOf("=");
		if (cut > 0) map.set(pair.slice(0, cut), pair.slice(cut + 1));
	}
	const p = (PERIODS as readonly string[]).includes(map.get("p") ?? "") ? (map.get("p") as PeriodKey) : DEFAULT_VIEW.p;
	const o = Number(map.get("o") ?? 0);
	const dims = (map.get("b") ?? "").split(".");
	const dim = (value: string | undefined, fallback: Dim) => ((DIMENSIONS as readonly string[]).includes(value ?? "") ? (value as Dim) : fallback);
	const f: Filters = {};
	for (const key of FILTER_KEYS) {
		const value = text(map.get(key));
		if (!value) continue;
		if (key === "bh") {
			if (isBehaviour(value)) f.bh = value;
		} else if (key === "ip") {
			if (parseNetwork(value)) f.ip = value;
		} else {
			f[key] = value;
		}
	}
	const n = Number(map.get("n") ?? 0);
	const al = Number(map.get("al") ?? 0);
	const d = text(map.get("d"));
	const at = Number(map.get("at") ?? 0);
	return {
		p,
		o: Number.isInteger(o) && o > 0 && o < 1000 ? o : 0,
		k: CODE_KIND[map.get("k") ?? ""] ?? null,
		f,
		b: [dim(dims[0], "ip"), dim(dims[1], "behaviour")],
		g: map.get("g") !== "0",
		n: Number.isInteger(n) && n > 0 && n < 10_000 ? n : 0,
		...(d && parseNetwork(d) && { d }),
		...(Number.isSafeInteger(al) && al > 0 && { al }),
		...(Number.isSafeInteger(at) && at > 0 && { at }),
	};
}

export type BucketSize = "5m" | "hour" | "day";

export interface Range {
	since: number;
	until: number;
	bucket: BucketSize;
	/** Can the period step back (◀) and forward (▶)? */
	steps: boolean;
}

const MINUTE = 60_000;
const HOUR = 3_600_000;

/** The period a view shows. Days are local days in `zone`. */
export function rangeOf(view: ExplorerView, now: Date, zone: string, retentionDays: number, lastVisit: string | null): Range {
	// A page past the first keeps the end the first page had.
	const t = view.at && view.at <= now.getTime() ? view.at : now.getTime();
	const rolling = (length: number, bucket: BucketSize): Range => {
		const until = t - view.o * length;
		return { since: until - length, until, bucket, steps: true };
	};
	const days = (count: number, steps: boolean): Range => {
		const today = localDay(t, zone);
		const lastDay = addDays(today, -view.o * count);
		const since = dayStart(addDays(lastDay, -(count - 1)), zone);
		const until = Math.min(t, dayStart(addDays(lastDay, 1), zone));
		return { since, until, bucket: "day", steps };
	};
	switch (view.p) {
		case "1h":
			return rolling(HOUR, "5m");
		case "24h":
			return rolling(24 * HOUR, "hour");
		case "3d":
			return rolling(72 * HOUR, "hour");
		case "7d":
			return days(7, true);
		case "30d":
			return days(30, true);
		case "ret":
			return days(retentionDays, false);
		case "visit": {
			const since = lastVisit ? Date.parse(lastVisit) : t - 24 * HOUR;
			return { since, until: t, bucket: t - since <= 72 * HOUR ? "hour" : "day", steps: false };
		}
	}
}

/** The local minute of an instant, to align buckets on local hours in zones with a half-hour offset. */
function localMinute(ms: number, zone: string): number {
	const parts = new Intl.DateTimeFormat("en-US", { timeZone: zone, minute: "2-digit" }).formatToParts(ms);
	return Number(parts.find((p) => p.type === "minute")?.value ?? 0);
}

/** The most bars a histogram of days draws. */
export const MAX_DAY_BARS = 45;

export interface Bucket {
	start: number;
	end: number;
}

/** The histogram's buckets: five minutes for an hour, hours up to three days, local days beyond. */
export function bucketsOf(range: Range, zone: string): Bucket[] {
	const out: Bucket[] = [];
	if (range.bucket === "day") {
		const days: Day[] = [];
		for (let day: Day = localDay(range.since, zone); days.length < 1000; day = addDays(day, 1)) {
			if (dayStart(day, zone) >= range.until) break;
			days.push(day);
		}
		// Up to 45 bars: a longer period takes two or more days a bar, so
		// the page stays inside the 2,000 nodes a Block Kit answer may hold.
		const per = Math.max(1, Math.ceil(days.length / MAX_DAY_BARS));
		for (let i = 0; i < days.length; i += per) {
			out.push({ start: dayStart(days[i]!, zone), end: dayStart(addDays(days[Math.min(days.length, i + per) - 1]!, 1), zone) });
		}
		return out;
	}
	const size = range.bucket === "5m" ? 5 * MINUTE : HOUR;
	let start = range.since - (range.since % MINUTE);
	start -= range.bucket === "hour" ? localMinute(start, zone) * MINUTE : (localMinute(start, zone) % 5) * MINUTE;
	for (; start < range.until && out.length < 500; start += size) out.push({ start, end: start + size });
	return out;
}

/** The value an alert has in a breakdown. */
export function valueOf(alert: LogAlert, dim: Dim): string {
	switch (dim) {
		case "ip":
			return alert.a;
		case "behaviour":
			return behaviourOf(alert.s);
		case "country":
			return alert.c;
		case "as":
			return alert.o;
		case "scenario":
			return alert.s;
		case "path":
			return alert.p;
		case "kind":
			return kindOfLog(alert);
		case "engine":
			return alert.m ?? "";
	}
}

/** The filter key a breakdown's value sets, when the value is clicked. */
export const FILTER_OF: Record<Dim, FilterKey | "k"> = { ip: "ip", behaviour: "bh", country: "cn", as: "as", scenario: "sc", path: "tg", kind: "k", engine: "en" };

/**
 * The alerts a view counts: in the period, of the kind, and matching every
 * filter. An address filter matches an address inside it when it is a range.
 * Blocklist alerts never reach the log, and are left out again here in case.
 */
export function select(alerts: LogAlert[], view: ExplorerView, range: Range): LogAlert[] {
	const net = view.f.ip ? parseNetwork(view.f.ip) : null;
	// An address filter matches the address, or every address inside it when it is a range.
	const within = (alert: LogAlert) => {
		if (!view.f.ip) return true;
		if (alert.a === view.f.ip) return true;
		const own = parseNetwork(alert.a);
		return Boolean(net && own && contains(net, own));
	};
	return alerts.filter(
		(a) =>
			a.t >= range.since &&
			a.t < range.until &&
			!isBlocklistScope(a.a) &&
			(!view.k || kindOfLog(a) === view.k) &&
			(!view.f.cn || a.c === view.f.cn) &&
			(!view.f.sc || a.s === view.f.sc) &&
			(!view.f.bh || behaviourOf(a.s) === view.f.bh) &&
			(!view.f.as || a.o === view.f.as) &&
			(!view.f.tg || a.p === view.f.tg) &&
			(!view.f.en || a.m === view.f.en) &&
			(!view.d || a.a === view.d) &&
			within(a),
	);
}

export interface Breakdown {
	dim: Dim;
	total: number;
	top: Array<{ value: string; alerts: number; share: number }>;
	other: number;
	/** Per bucket: the top values' counts in order, then Other. */
	series: number[][];
}

/** The top three values of a dimension, the rest as Other, and their counts per bucket. */
export function breakdown(alerts: LogAlert[], dim: Dim, buckets: Bucket[], topCount = 3): Breakdown {
	const counts = new Map<string, number>();
	for (const a of alerts) {
		const v = valueOf(a, dim);
		counts.set(v, (counts.get(v) ?? 0) + 1);
	}
	const total = alerts.length;
	const top = [...counts.entries()]
		.sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
		.slice(0, topCount)
		.map(([value, n]) => ({ value, alerts: n, share: total ? n / total : 0 }));
	const index = new Map(top.map((t, i) => [t.value, i]));
	const series = Array.from({ length: top.length + 1 }, () => new Array<number>(buckets.length).fill(0));
	let b = 0;
	const sorted = [...alerts].sort((x, y) => x.t - y.t);
	for (const a of sorted) {
		while (b < buckets.length - 1 && a.t >= buckets[b]!.end) b++;
		const i = index.get(valueOf(a, dim)) ?? top.length;
		series[i]![b]!++;
	}
	return { dim, total, top, other: total - top.reduce((n, t) => n + t.alerts, 0), series };
}

export interface IpGroup {
	ip: string;
	country: string;
	asName: string;
	alerts: number;
	first: number;
	last: number;
	waf: number;
	scenarios: Array<[string, number]>;
	paths: Array<[string, number]>;
	decisions: number;
	/** The CrowdSec agents that raised its alerts, most alerts first. Alerts stored by 0.1.0 have none. */
	engines: string[];
	/** When the address's last known decision ends, if it is in the future. */
	bannedUntil?: number;
}

/** Alerts grouped by source address, the latest alert first. */
export function groupByIp(alerts: LogAlert[], now: Date): IpGroup[] {
	const groups = new Map<string, { g: IpGroup; scen: Map<string, number>; paths: Map<string, number>; engines: Map<string, number> }>();
	for (const a of alerts) {
		let entry = groups.get(a.a);
		if (!entry) {
			entry = {
				g: { ip: a.a, country: a.c, asName: a.o, alerts: 0, first: a.t, last: a.t, waf: 0, scenarios: [], paths: [], decisions: 0, engines: [] },
				scen: new Map(),
				paths: new Map(),
				engines: new Map(),
			};
			groups.set(a.a, entry);
		}
		const g = entry.g;
		g.alerts++;
		g.first = Math.min(g.first, a.t);
		g.last = Math.max(g.last, a.t);
		if (a.k === "w") g.waf++;
		g.decisions += a.d;
		if (a.u && a.u > now.getTime() && (!g.bannedUntil || a.u > g.bannedUntil)) g.bannedUntil = a.u;
		entry.scen.set(a.s, (entry.scen.get(a.s) ?? 0) + 1);
		if (a.p) entry.paths.set(a.p, (entry.paths.get(a.p) ?? 0) + 1);
		if (a.m) entry.engines.set(a.m, (entry.engines.get(a.m) ?? 0) + 1);
	}
	const rank = (m: Map<string, number>) => [...m.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
	return [...groups.values()]
		.map(({ g, scen, paths, engines }) => ({ ...g, scenarios: rank(scen), paths: rank(paths), engines: rank(engines).map(([e]) => e) }))
		.sort((x, y) => y.last - x.last || x.ip.localeCompare(y.ip));
}

/**
 * Whole percentages that add up to 100, by the largest remainder: three
 * values of one alert each show 34, 33 and 33, not 33 three times.
 */
export function percents(counts: number[]): number[] {
	const total = counts.reduce((n, c) => n + c, 0);
	if (total === 0) return counts.map(() => 0);
	const exact = counts.map((c) => (c * 100) / total);
	const out = exact.map(Math.floor);
	const order = exact.map((e, i) => [e - Math.floor(e), i] as const).sort((a, b) => b[0] - a[0] || a[1] - b[1]);
	for (let k = 0, left = 100 - out.reduce((n, p) => n + p, 0); k < left; k++) out[order[k]![1]]!++;
	return out;
}

/** A view with one change, which is reset to the table's first page unless the change is the page. */
export function withView(view: ExplorerView, change: Partial<ExplorerView>): ExplorerView {
	const next = { ...view, ...change };
	// Any change but the page starts again from the first page, now.
	if (!("n" in change)) {
		next.n = 0;
		if (!("at" in change)) delete next.at;
	}
	if (!("al" in change) && "d" in change) delete next.al;
	return next;
}

export function withFilter(view: ExplorerView, key: FilterKey | "k", value: string | null): ExplorerView {
	if (key === "k") return withView(view, { k: value && KINDS.includes(value as Kind) ? (value as Kind) : null });
	const f = { ...view.f };
	if (value) (f as Record<string, string>)[key] = value;
	else delete f[key];
	return withView(view, { f });
}
