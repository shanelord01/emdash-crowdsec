/**
 * The Security page: 7, 30 or 90 days of alerts from the stored day rows.
 *
 * It reads storage only. Top lists are sums of each day's top 25, so a
 * value that never made a day's top 25 is undercounted. Over a range the
 * leaders are the same, and the page says the lists are approximate.
 * Block Kit keeps no state, so the chosen range travels in the buttons'
 * `value`.
 */

import type { PluginContext } from "emdash/plugin";

import { t, type Lang } from "../i18n.js";
import type { SourceId } from "../settings.js";
import { daysStore, BIND_LIMIT } from "../store/access.js";
import { ranked, sumMaps, type DayRow } from "../store/rows.js";
import { coveredSince, type SyncState } from "../sync/scheduler.js";
import { addDays, daysBetween, localDay, type Day } from "../sync/time.js";
import { actions, button, CHART_COLOURS, columns, context, dailyChart, empty, header, link, stats, table, type SecurityBlock } from "./blocks.js";
import { comparisonText, countryName, formatAge, formatCount, formatDay, formatShortDay, trendOf } from "./format.js";
import { ALERTS_PATH, DECISIONS_PATH, PAGE_REFRESH, RANGE_ACTION, SETUP_ACTION } from "./ids.js";
import { emptyReason, statusLine } from "./status.js";

export const RANGES = [7, 30, 90] as const;
export type RangeDays = (typeof RANGES)[number];
export const DEFAULT_RANGE: RangeDays = 30;
const TOP_ROWS = 10;

export function parseRange(value: unknown): RangeDays {
	const n = typeof value === "string" ? Number(value) : value;
	return (RANGES as readonly unknown[]).includes(n) ? (n as RangeDays) : DEFAULT_RANGE;
}

export interface SecurityInput {
	state: SyncState;
	source: SourceId;
	zone: string;
	range: RangeDays;
	/** Day rows for the range and the equal period before it. */
	days: DayRow[];
	now: Date;
	lang: Lang;
}

/** Day rows since the start of the previous period. Calls: one or two queries of 100 days. */
export async function loadDays(ctx: PluginContext, since: Day): Promise<DayRow[]> {
	const store = daysStore(ctx);
	const out: DayRow[] = [];
	let cursor: string | undefined;
	for (let i = 0; store && i < 2; i++) {
		const page = await store.query({
			where: { date: { gte: since } },
			orderBy: { date: "asc" },
			limit: BIND_LIMIT,
			...(cursor ? { cursor } : {}),
		});
		out.push(...page.items.map((item) => item.data));
		if (!page.hasMore || !page.cursor) break;
		cursor = page.cursor;
	}
	return out;
}

export function renderSecurity(input: SecurityInput): SecurityBlock[] {
	const { state, range, days, now, lang } = input;
	const today = localDay(now, input.zone);
	const start = addDays(today, -(range - 1));
	const previousStart = addDays(today, -(range * 2 - 1));
	const inRange = days.filter((d) => daysBetween(start, d.date) >= 0 && daysBetween(d.date, today) >= 0);
	const before = days.filter((d) => daysBetween(previousStart, d.date) >= 0 && daysBetween(d.date, addDays(start, -1)) >= 0);

	if (days.length === 0) {
		return [
			controls(range, lang),
			empty({ title: t(lang, "noDataYet"), description: emptyReason(state, lang) }),
		];
	}

	const covered = coveredSince(state);
	const hasPrevious = covered !== null && localDay(covered, input.zone) <= previousStart;
	const sum = (rows: DayRow[], key: "alerts" | "bans" | "waf") => rows.reduce((n, row) => n + row[key], 0);
	const stat = (label: string, key: "alerts" | "bans" | "waf") => {
		const current = sum(inRange, key);
		const previous = hasPrevious ? sum(before, key) : null;
		const trend = trendOf(current, previous);
		return {
			label,
			value: formatCount(current, lang),
			description: comparisonText(current, previous, lang),
			...(trend && { trend }),
		};
	};

	const out: SecurityBlock[] = [controls(range, lang)];
	out.push(
		stats([
			stat(t(lang, "alertsInRange", { days: range }), "alerts"),
			stat(t(lang, "bansInRange", { days: range }), "bans"),
			stat(t(lang, "wafInRange", { days: range }), "waf"),
			{
				label: t(lang, "activeBans"),
				value: state.active ? `${formatCount(state.active.bans, lang)}${state.active.truncated ? "+" : ""}` : "-",
				description: state.active ? t(lang, "asOf", { age: formatAge(state.active.at, now, lang) ?? "" }) : t(lang, "notCountedYet"),
			},
		]),
	);

	// Every day of the range, oldest first. A day without a row is a gap
	// before stored history starts, and zero after it.
	const byDay = new Map(inRange.map((d) => [d.date, d]));
	const coveredDay = covered ? localDay(covered, input.zone) : today;
	const dayKeys = Array.from({ length: range }, (_, i) => addDays(start, i));
	const labels = dayKeys.map((day) => formatShortDay(day, lang));
	const values = (pick: (d: DayRow) => number) =>
		dayKeys.map((day) => {
			const row = byDay.get(day);
			return row ? pick(row) : day >= coveredDay ? 0 : null;
		});
	out.push(header(t(lang, "alertsByDay")));
	out.push(
		dailyChart({
			labels,
			series: [
				{ name: t(lang, "kindBehaviour"), data: values((d) => d.behaviour), colour: CHART_COLOURS[0] },
				{ name: t(lang, "kindWaf"), data: values((d) => d.waf), colour: CHART_COLOURS[1] },
				{ name: t(lang, "kindBot"), data: values((d) => d.bot), colour: CHART_COLOURS[2] },
				{ name: t(lang, "kindManual"), data: values((d) => d.manual), colour: CHART_COLOURS[3] },
			],
			style: "bar",
			height: 280,
			blockId: "cs:chart:alerts",
		}),
	);
	out.push(header(t(lang, "bansByDay")));
	out.push(
		dailyChart({
			labels,
			series: [{ name: t(lang, "bansIssued"), data: values((d) => d.bans), colour: CHART_COLOURS[4] }],
			style: "bar",
			height: 200,
			blockId: "cs:chart:bans",
		}),
	);

	const notes = [statusLine(state, input.source, now, lang, input.zone)];
	const oldest = days.reduce<Day | undefined>((min, d) => (min === undefined || d.date < min ? d.date : min), undefined);
	if (oldest && oldest > start) notes.push(t(lang, "historyStarts", { date: formatDay(oldest, lang) }));
	out.push(context(notes.join(" · ")));

	const country = countryName(lang);
	out.push(
		columns([
			[header(t(lang, "topScenarios")), topTable("cs:top:scenarios", t(lang, "colScenario"), sumMaps(inRange.map((d) => d.scenarios)), lang, "code")],
			[header(t(lang, "topSources")), topTable("cs:top:ips", t(lang, "colAddress"), sumMaps(inRange.map((d) => d.ips)), lang, "code")],
		]),
	);
	out.push(
		columns([
			[header(t(lang, "topCountries")), topTable("cs:top:countries", t(lang, "colCountry"), sumMaps(inRange.map((d) => d.countries)), lang, "text", country)],
			[header(t(lang, "topAsNames")), topTable("cs:top:as", t(lang, "colAsName"), sumMaps(inRange.map((d) => d.asNames)), lang, "text")],
		]),
	);
	out.push(header(t(lang, "topPaths")));
	out.push(topTable("cs:top:paths", t(lang, "colPath"), sumMaps(inRange.map((d) => d.paths)), lang, "code"));
	out.push(context(t(lang, "topListsNote", { zone: input.zone })));
	return out;
}

function topTable(
	blockId: string,
	label: string,
	map: Record<string, number>,
	lang: Lang,
	format: "text" | "code",
	display: (value: string) => string = (v) => v,
) {
	return table({
		blockId,
		pageActionId: `${blockId}:page`,
		columns: [
			{ key: "value", label, format },
			{ key: "alerts", label: t(lang, "colAlerts"), format: "number" },
		],
		rows: ranked(map)
			.slice(0, TOP_ROWS)
			.map(([value, alerts]) => ({ value: display(value), alerts })),
		emptyText: t(lang, "nothingRecorded"),
	});
}

function controls(range: RangeDays, lang: Lang) {
	return actions(
		[
			...RANGES.map((days) =>
				button(RANGE_ACTION, t(lang, "rangeDays", { count: days }), { style: days === range ? "primary" : "secondary", value: days }),
			),
			button(PAGE_REFRESH, t(lang, "refresh"), { style: "secondary", value: range }),
			link(t(lang, "alertsPage"), { kind: "plugin-page", path: ALERTS_PATH }, { appearance: "secondary" }),
			link(t(lang, "decisionsPage"), { kind: "plugin-page", path: DECISIONS_PATH }, { appearance: "secondary" }),
			button(SETUP_ACTION, t(lang, "checkSetup"), { style: "secondary", value: range }),
		],
		{ blockId: "cs:controls" },
	);
}
