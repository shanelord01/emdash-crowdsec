/**
 * The Security page: the last 24 hours, or 7, 30 or 90 days.
 *
 * Everything here is read from the plugin's own storage and state, which
 * the sync fills from the site's own LAPI and Prometheus endpoints. Nothing
 * is asked of CrowdSec's cloud.
 *
 * - Alerts come from the stored day rows, and for the 24-hour view from the
 *   hourly buckets the sync keeps for 48 hours.
 * - Traffic (packets discarded, web requests, bot challenges) comes from
 *   the stored traffic days and, for 24 hours, the sampler's hourly
 *   differences. It shows once a metrics URL is set.
 * - Active bans by source come from the engine's latest gauges.
 *
 * Top lists are sums of each day's top 25, so a value that never made a
 * day's top 25 is undercounted. EmDash draws no chart legend, so a line
 * under each chart names its series and colours, which are set explicitly.
 * Block Kit keeps no state, so the range travels in the buttons' values,
 * and each button has an action id of its own.
 */

import type { PluginContext } from "emdash/plugin";

import { t, type Lang, type MessageKey } from "../i18n.js";
import { discarded, ORIGIN_GROUPS, sumCounters, CHALLENGE_STAGES, type Counters, type OriginGroup } from "../metrics/sample.js";
import { daysStore, trafficStore, BIND_LIMIT } from "../store/access.js";
import { ranked, sumMaps, type DayRow, type TrafficDay } from "../store/rows.js";
import { coveredSince, sumHours, type MetricsState, type SyncState } from "../sync/scheduler.js";
import { addDays, daysBetween, hourKey, localDay, type Day } from "../sync/time.js";
import {
	actions,
	button,
	CHART_COLOURS,
	columns,
	context,
	dailyChart,
	empty,
	header,
	link,
	meter,
	stats,
	table,
	type DailySeries,
	type SecurityBlock,
} from "./blocks.js";
import { comparisonText, countryName, engineLabel, formatAge, formatBytes, formatCount, formatHour, formatShort, formatShortDay, trendOf } from "./format.js";
import { ALERTS_PATH, DECISIONS_PATH, PAGE_REFRESH, RANGE_ACTION, SETUP_ACTION } from "./ids.js";
import { emptyReason, statusLine } from "./status.js";

/** 1 is the last 24 hours, by hour. The others are days. */
export const RANGES = [1, 7, 30, 90] as const;
export type RangeDays = (typeof RANGES)[number];
export const DEFAULT_RANGE: RangeDays = 30;
const TOP_ROWS = 10;
const HOUR_MS = 3_600_000;

export function parseRange(value: unknown): RangeDays {
	const n = typeof value === "string" ? Number(value) : value;
	return (RANGES as readonly unknown[]).includes(n) ? (n as RangeDays) : DEFAULT_RANGE;
}

/** The range button's own action id: `cs:range:24h`, `cs:range:7d`. */
export function rangeActionId(range: RangeDays): string {
	return `${RANGE_ACTION}:${range === 1 ? "24h" : `${range}d`}`;
}

/** The chart colours, by name, so the series line can say which is which. */
const COLOUR_KEYS: MessageKey[] = ["m1h", "m1i", "m1j", "m1k", "m1l", "m1m"];

const ORIGIN_COLOUR: Record<OriginGroup, number> = { community: 0, detections: 1, manual: 2, other: 4 };
const ORIGIN_LABEL: Record<OriginGroup, MessageKey> = {
	community: "m1n",
	detections: "m1o",
	manual: "m1p",
	other: "m1q",
};

/** The line under a chart that names its series by colour. */
export function seriesLine(lang: Lang, items: Array<{ name: string; colour: number }>): SecurityBlock {
	return context(items.map((item) => `${t(lang, COLOUR_KEYS[item.colour % COLOUR_KEYS.length]!)}: ${item.name}`).join(" · "));
}

export interface SecurityInput {
	state: SyncState;
	zone: string;
	range: RangeDays;
	/** Day rows for the range and the equal period before it (two local days for the 24-hour view). */
	days: DayRow[];
	traffic: TrafficDay[];
	metrics: MetricsState | null;
	/** The Engine names setting, for the alerts-by-engine chart. */
	engineNames?: Record<string, string>;
	/** True when a metrics URL is set. */
	metricsOn: boolean;
	now: Date;
	lang: Lang;
}

/** Rows since a day, a query of 100 at a time. Calls: one or two. */
async function loadSince<T>(store: ReturnType<typeof daysStore> | ReturnType<typeof trafficStore>, since: Day): Promise<T[]> {
	const out: T[] = [];
	let cursor: string | undefined;
	for (let i = 0; store && i < 2; i++) {
		const page = await store.query({
			where: { date: { gte: since } },
			orderBy: { date: "asc" },
			limit: BIND_LIMIT,
			...(cursor ? { cursor } : {}),
		});
		out.push(...page.items.map((item) => item.data as T));
		if (!page.hasMore || !page.cursor) break;
		cursor = page.cursor;
	}
	return out;
}

/** Day rows since the start of the previous period. Calls: one or two queries of 100 days. */
export async function loadDays(ctx: PluginContext, since: Day): Promise<DayRow[]> {
	return await loadSince<DayRow>(daysStore(ctx), since);
}

/** Traffic days since a day. Calls: one or two queries. */
export async function loadTraffic(ctx: PluginContext, since: Day): Promise<TrafficDay[]> {
	return await loadSince<TrafficDay>(trafficStore(ctx), since);
}

/** The first day a range's page reads, the previous period included. */
export function readSince(range: RangeDays, today: Day): Day {
	return range === 1 ? addDays(today, -1) : addDays(today, -(range * 2 - 1));
}

export function renderSecurity(input: SecurityInput): SecurityBlock[] {
	const { state, range, days, now, lang, zone } = input;
	const today = localDay(now, zone);
	const out: SecurityBlock[] = [controls(range, lang)];

	if (days.length === 0 && !state.lastSync && !input.metrics) {
		out.push(empty({ title: t(lang, "m0"), description: emptyReason(state, lang) }));
		return out;
	}

	const view = range === 1 ? hourlyView(input) : dailyView(input, today);

	out.push(stats([...view.alertStats, activeStat(input)]));
	out.push(context(statusLine(state, now, lang, zone)));

	if (input.metricsOn) out.push(...trafficSection(input, view));

	out.push(header(range === 1 ? t(lang, "m1d") : t(lang, "ml")));
	const kinds: Array<[keyof DayRow & ("behaviour" | "waf" | "bot" | "manual"), MessageKey, number]> = [
		["behaviour", "mb", 0],
		["waf", "m9", 1],
		["bot", "ma", 2],
		["manual", "mc", 3],
	];
	const kindSeries = kinds.map(([key, label, colour]) => ({ name: t(lang, label), data: view.alertValues(key), colour: CHART_COLOURS[colour]! }));
	out.push(dailyChart({ labels: view.labels, series: kindSeries, style: "bar", height: 280, blockId: "cs:chart:alerts" }));
	out.push(seriesLine(lang, kinds.map(([, label, colour]) => ({ name: t(lang, label), colour }))));

	out.push(header(range === 1 ? t(lang, "m1e") : t(lang, "mm")));
	out.push(
		dailyChart({
			labels: view.labels,
			series: [{ name: t(lang, "mn"), data: view.alertValues("bans"), colour: CHART_COLOURS[4] }],
			style: "bar",
			height: 200,
			blockId: "cs:chart:bans",
		}),
	);
	out.push(seriesLine(lang, [{ name: t(lang, "mn"), colour: 4 }]));

	const inRange = view.topDays;
	const country = countryName(lang);
	const countries = ranked(sumMaps(inRange.map((d) => d.countries))).slice(0, TOP_ROWS);
	out.push(header(t(lang, "m1f")));
	if (countries.length > 0) {
		out.push(
			dailyChart({
				labels: countries.map(([code]) => country(code)),
				series: [{ name: t(lang, "mh"), data: countries.map(([, n]) => n), colour: CHART_COLOURS[0] }],
				style: "bar",
				horizontal: true,
				height: Math.max(160, countries.length * 28 + 48),
				blockId: "cs:chart:countries",
			}),
		);
		out.push(seriesLine(lang, [{ name: t(lang, "m1g"), colour: 0 }]));
	} else {
		out.push(context(t(lang, "m1")));
	}

	// Alerts by the CrowdSec agent that raised them, when more than one did:
	// a central LAPI hears from several hosts, and a single host sees no change.
	const engines = ranked(sumMaps(inRange.map((d) => d.machines ?? {}))).slice(0, TOP_ROWS);
	if (engines.length > 1) {
		out.push(header(t(lang, "m2m")));
		out.push(
			dailyChart({
				labels: engines.map(([id]) => engineLabel(id, input.engineNames, lang)),
				series: [{ name: t(lang, "mh"), data: engines.map(([, n]) => n), colour: CHART_COLOURS[3] }],
				style: "bar",
				horizontal: true,
				height: Math.max(120, engines.length * 28 + 48),
				blockId: "cs:chart:engines",
			}),
		);
		out.push(seriesLine(lang, [{ name: t(lang, "m2n"), colour: 3 }]));
	}

	out.push(
		columns([
			[header(t(lang, "mo")), topTable("cs:top:scenarios", t(lang, "mv"), sumMaps(inRange.map((d) => d.scenarios)), lang, "code")],
			[header(t(lang, "mp")), topTable("cs:top:ips", t(lang, "mw"), sumMaps(inRange.map((d) => d.ips)), lang, "code")],
		]),
	);
	out.push(
		columns([
			[header(t(lang, "mq")), topTable("cs:top:countries", t(lang, "mx"), sumMaps(inRange.map((d) => d.countries)), lang, "text", country)],
			[header(t(lang, "mr")), topTable("cs:top:as", t(lang, "my"), sumMaps(inRange.map((d) => d.asNames)), lang, "text")],
		]),
	);
	out.push(header(t(lang, "ms")));
	out.push(topTable("cs:top:paths", t(lang, "m10"), sumMaps(inRange.map((d) => d.paths)), lang, "code"));
	out.push(context([t(lang, "mt", { zone }), ...(range === 1 ? [t(lang, "mu")] : [])].join(" ")));
	return out;
}

interface View {
	labels: string[];
	alertStats: Array<{ label: string; value: string; description?: string; trend?: "up" | "down" | "neutral" }>;
	alertValues: (key: "behaviour" | "waf" | "bot" | "manual" | "bans") => Array<number | null>;
	/** Traffic counters per bucket, and summed over the range and the period before. */
	trafficBuckets: Counters[];
	traffic: Counters;
	trafficBefore: Counters | null;
	/** Day rows the top lists sum. */
	topDays: DayRow[];
}

function hourlyView(input: SecurityInput): View {
	const { state, lang, now, zone } = input;
	const nowMs = now.getTime();
	const startHour = Math.floor(nowMs / HOUR_MS) * HOUR_MS - 23 * HOUR_MS;
	const hours = Array.from({ length: 24 }, (_, i) => startHour + i * HOUR_MS);
	const covered = coveredSince(state);
	const reach = covered ? Date.parse(covered) : Number.POSITIVE_INFINITY;
	const bucket = (ms: number) => state.hours?.[hourKey(ms)];
	const current = sumHours(state, nowMs - 24 * HOUR_MS, nowMs + HOUR_MS);
	const before = reach <= nowMs - 48 * HOUR_MS ? sumHours(state, nowMs - 48 * HOUR_MS, nowMs - 24 * HOUR_MS) : null;
	const stat = (label: string, cur: number, prev: number | null) => {
		const trend = trendOf(cur, prev);
		return { label, value: formatCount(cur, lang), description: comparisonText(cur, prev, lang), ...(trend && { trend }) };
	};
	const metricHours = input.metrics?.hours ?? {};
	const sampled = input.metrics ? Date.parse(input.metrics.since) : Number.POSITIVE_INFINITY;
	const trafficHours = (from: number, to: number) =>
		sumCounters(Object.entries(metricHours).filter(([key]) => Date.parse(`${key}:00:00.000Z`) >= from && Date.parse(`${key}:00:00.000Z`) < to).map(([, c]) => c));
	const today = localDay(now, zone);
	return {
		labels: hours.map((ms) => formatHour(ms, zone)),
		alertStats: [
			stat(t(lang, "alerts24h"), current.alerts, before?.alerts ?? null),
			stat(t(lang, "bans24h"), current.bans ?? 0, before ? (before.bans ?? 0) : null),
			stat(t(lang, "waf24h"), current.waf, before?.waf ?? null),
		],
		alertValues: (key) => hours.map((ms) => (ms + HOUR_MS <= reach ? null : (bucket(ms)?.[key] ?? 0))),
		trafficBuckets: hours.map((ms) => (ms + HOUR_MS <= sampled ? {} : (metricHours[hourKey(ms)] ?? {}))),
		traffic: trafficHours(nowMs - 24 * HOUR_MS, nowMs + HOUR_MS),
		trafficBefore: sampled <= nowMs - 48 * HOUR_MS ? trafficHours(nowMs - 48 * HOUR_MS, nowMs - 24 * HOUR_MS) : null,
		topDays: input.days.filter((d) => d.date === today || d.date === addDays(today, -1)),
	};
}

function dailyView(input: SecurityInput, today: Day): View {
	const { state, range, days, lang, zone } = input;
	const start = addDays(today, -(range - 1));
	const previousStart = addDays(today, -(range * 2 - 1));
	const within = (d: { date: Day }, from: Day, to: Day) => daysBetween(from, d.date) >= 0 && daysBetween(d.date, to) >= 0;
	const inRange = days.filter((d) => within(d, start, today));
	const before = days.filter((d) => within(d, previousStart, addDays(start, -1)));
	const covered = coveredSince(state);
	const hasPrevious = covered !== null && localDay(covered, zone) <= previousStart;
	const sum = (rows: DayRow[], key: "alerts" | "bans" | "waf") => rows.reduce((n, row) => n + row[key], 0);
	const stat = (label: string, key: "alerts" | "bans" | "waf") => {
		const current = sum(inRange, key);
		const previous = hasPrevious ? sum(before, key) : null;
		const trend = trendOf(current, previous);
		return { label, value: formatCount(current, lang), description: comparisonText(current, previous, lang), ...(trend && { trend }) };
	};
	const dayKeys = Array.from({ length: range }, (_, i) => addDays(start, i));
	const byDay = new Map(inRange.map((d) => [d.date, d]));
	const coveredDay = covered ? localDay(covered, zone) : today;
	const traffic = new Map(input.traffic.map((d) => [d.date, d]));
	const sampledDay = input.metrics ? localDay(input.metrics.since, zone) : null;
	const trafficIn = (from: Day, to: Day) => sumCounters(input.traffic.filter((d) => within(d, from, to)).map((d) => d.counters));
	// Ninety days are drawn in three-day bars: a bar a day would pass the
	// 2,000 nodes a Block Kit answer may hold once traffic charts are on.
	const per = range > 30 ? 3 : 1;
	const groups = Array.from({ length: Math.ceil(dayKeys.length / per) }, (_, i) => dayKeys.slice(i * per, (i + 1) * per));
	return {
		labels: groups.map((g) => (per === 1 ? formatShortDay(g[0]!, lang) : t(lang, "m2h", { from: formatShortDay(g[0]!, lang), to: formatShortDay(g[g.length - 1]!, lang) }))),
		alertStats: [
			stat(t(lang, "mi", { days: range }), "alerts"),
			stat(t(lang, "mj", { days: range }), "bans"),
			stat(t(lang, "mk", { days: range }), "waf"),
		],
		alertValues: (key) =>
			groups.map((g) => {
				const values = g.map((day) => {
					const row = byDay.get(day);
					return row ? row[key] : day >= coveredDay ? 0 : null;
				});
				return values.every((v) => v === null) ? null : values.reduce<number>((n, v) => n + (v ?? 0), 0);
			}),
		trafficBuckets: groups.map((g) => sumCounters(g.map((day) => traffic.get(day)?.counters ?? {}))),
		traffic: trafficIn(start, today),
		trafficBefore: sampledDay !== null && sampledDay < previousStart ? trafficIn(previousStart, addDays(start, -1)) : null,
		topDays: inRange,
	};
}

function activeStat(input: SecurityInput) {
	const { state, now, lang } = input;
	return {
		label: t(lang, "md"),
		value: state.active ? `${formatCount(state.active.bans, lang)}${state.active.truncated ? "+" : ""}` : "-",
		description: state.active ? t(lang, "me", { age: formatAge(state.active.at, now, lang) ?? "" }) : t(lang, "mf"),
	};
}

/**
 * Packets discarded by origin, the share of traffic discarded, web
 * requests and bot challenges, and active bans by source.
 */
function trafficSection(input: SecurityInput, view: View): SecurityBlock[] {
	const { lang, metrics, now, range } = input;
	const out: SecurityBlock[] = [header(t(lang, "m1r"))];
	if (!metrics) {
		out.push(context(t(lang, "m1s")));
		return out;
	}
	const packets = discarded(view.traffic, "packets");
	const bytes = discarded(view.traffic, "bytes");
	const before = view.trafficBefore ? discarded(view.trafficBefore, "packets") : null;
	const trend = trendOf(packets.total, before?.total ?? null);
	out.push(
		stats([
			{
				label: t(lang, "m1t"),
				value: formatShort(packets.total, lang),
				description: `${formatBytes(bytes.total, lang)} · ${comparisonText(packets.total, before?.total ?? null, lang)}`,
				...(trend && { trend }),
			},
			...(["community", "detections", "manual"] as const).map((group) => ({
				label: t(lang, ORIGIN_LABEL[group]),
				value: formatShort(packets[group], lang),
				description: formatBytes(bytes[group], lang),
			})),
		]),
	);
	const shown = ORIGIN_GROUPS.filter((g) => g !== "other" || packets.other > 0);
	const series: DailySeries[] = shown.map((group) => ({
		name: t(lang, ORIGIN_LABEL[group]),
		data: view.trafficBuckets.map((c) => c[`drop.packets.${group}`] ?? 0),
		colour: CHART_COLOURS[ORIGIN_COLOUR[group]],
	}));
	out.push(dailyChart({ labels: view.labels, series, style: "bar", height: 260, blockId: "cs:chart:discarded" }));
	out.push(seriesLine(lang, shown.map((group) => ({ name: t(lang, ORIGIN_LABEL[group]), colour: ORIGIN_COLOUR[group] }))));

	const processed = view.traffic["proc.packets"] ?? 0;
	if (processed > 0) {
		const share = Math.min(1, packets.total / processed);
		out.push(
			meter({
				label: t(lang, "m1u"),
				value: Math.round(share * 1000) / 10,
				max: 100,
				customValue: t(lang, "m1v", { share: new Intl.NumberFormat("en-AU", { style: "percent", maximumFractionDigits: 1 }).format(share), processed: formatShort(processed, lang) }),
				blockId: "cs:meter:share",
			}),
		);
	}

	out.push(header(t(lang, "m1w")));
	out.push(
		dailyChart({
			labels: view.labels,
			series: [
				{ name: t(lang, "m1x"), data: view.trafficBuckets.map((c) => c["as.reqs"] ?? 0), colour: CHART_COLOURS[3] },
				{ name: t(lang, "m1y"), data: view.trafficBuckets.map((c) => c["as.blocks"] ?? 0), colour: CHART_COLOURS[5] },
			],
			style: "line",
			height: 240,
			blockId: "cs:chart:requests",
		}),
	);
	out.push(seriesLine(lang, [{ name: t(lang, "m1x"), colour: 3 }, { name: t(lang, "m1y"), colour: 5 }]));
	const funnel = CHALLENGE_STAGES.map((stage) => view.traffic[`ch.${stage}`] ?? 0);
	if (funnel.some((n) => n > 0)) {
		out.push(header(t(lang, "m1z")));
		out.push(
			dailyChart({
				labels: CHALLENGE_STAGES.map((stage) => t(lang, `challenge_${stage}` as MessageKey)),
				series: [{ name: t(lang, "challenges"), data: funnel, colour: CHART_COLOURS[2] }],
				style: "bar",
				height: 220,
				blockId: "cs:chart:challenge",
			}),
		);
		out.push(seriesLine(lang, [{ name: t(lang, range === 1 ? "m20" : "m21", { days: range }), colour: 2 }]));
	}

	const gauges = metrics.gauges;
	if (gauges) {
		out.push(header(t(lang, "m22")));
		const groups = ORIGIN_GROUPS.filter((g) => gauges.bansByOrigin[g] > 0 || g !== "other");
		out.push(
			dailyChart({
				labels: groups.map((g) => t(lang, ORIGIN_LABEL[g])),
				series: [{ name: t(lang, "m23"), data: groups.map((g) => gauges.bansByOrigin[g]), colour: CHART_COLOURS[0] }],
				style: "bar",
				horizontal: true,
				height: 180,
				blockId: "cs:chart:sources",
			}),
		);
		out.push(seriesLine(lang, [{ name: t(lang, "m24"), colour: 0 }]));
		out.push(
			table({
				blockId: "cs:top:community",
				pageActionId: "cs:top:community:page",
				columns: [
					{ key: "reason", label: t(lang, "m25"), format: "code" },
					{ key: "decisions", label: t(lang, "m26"), format: "number" },
				],
				rows: ranked(gauges.communityReasons)
					.slice(0, TOP_ROWS)
					.map(([reason, decisions]) => ({ reason, decisions })),
				emptyText: t(lang, "m1"),
			}),
		);
	}
	out.push(context(t(lang, "m27", { age: formatAge(metrics.since, now, lang) ?? "" })));
	return out;
}


function topTable(blockId: string, label: string, map: Record<string, number>, lang: Lang, format: "text" | "code", display: (value: string) => string = (v) => v) {
	return table({
		blockId,
		pageActionId: `${blockId}:page`,
		columns: [
			{ key: "value", label, format },
			{ key: "alerts", label: t(lang, "mh"), format: "number" },
		],
		rows: ranked(map)
			.slice(0, TOP_ROWS)
			.map(([value, alerts]) => ({ value: display(value), alerts })),
		emptyText: t(lang, "m1"),
	});
}

function controls(range: RangeDays, lang: Lang) {
	return actions(
		[
			...RANGES.map((days) =>
				button(rangeActionId(days), days === 1 ? t(lang, "range24h") : t(lang, "m2", { count: days }), {
					style: days === range ? "primary" : "secondary",
					value: days,
				}),
			),
			button(PAGE_REFRESH, t(lang, "refresh"), { style: "secondary", value: range }),
			link(t(lang, "m6"), { kind: "plugin-page", path: ALERTS_PATH }, { appearance: "secondary" }),
			link(t(lang, "m7"), { kind: "plugin-page", path: DECISIONS_PATH }, { appearance: "secondary" }),
			button(SETUP_ACTION, t(lang, "m8"), { style: "secondary", value: range }),
		],
		{ blockId: "cs:controls" },
	);
}

