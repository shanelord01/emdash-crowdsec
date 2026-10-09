/**
 * The Alerts explorer (`/security/alerts`, "CrowdSec alerts").
 *
 * A period bar, kind tabs, filters shown as removable chips, two breakdown
 * panels each with its top three values and a stacked histogram, and the
 * alerts grouped by source address, with a view of one address and a live
 * detail of one alert. Everything comes from the alert log the sync keeps
 * (`src/store/log.ts`) and, for an alert's detail, one live
 * `GET /v1/alerts/{id}` from the site's own LAPI. Nothing is asked of
 * CrowdSec's cloud, so there are no reputation badges: the hints are local
 * ("Banned now" from a decision still running, "Seen before" from alerts
 * on days before the period).
 *
 * Every control's action id carries the view it leads to, so no two
 * controls share one.
 */

import type { PluginContext } from "emdash/plugin";

import { t, type Lang, type MessageKey } from "../i18n.js";
import type { RawAlert } from "../lapi/types.js";
import { daysStore, logStore, BIND_LIMIT } from "../store/access.js";
import { flatten, kindOfLog, type LogAlert, type LogRow } from "../store/log.js";
import { KINDS, type Kind } from "../store/rows.js";
import { localDay, parseGoDuration } from "../sync/time.js";
import { BAN_DURATIONS, DELETE_GRACE_S, type BanCheck, type BanInput } from "../write/actions.js";
import { BEHAVIOURS, type Behaviour } from "../explorer/behaviour.js";
import {
	breakdown,
	bucketsOf,
	decodeView,
	DEFAULT_VIEW,
	DIMENSIONS,
	encodeView,
	FILTER_KEYS,
	FILTER_OF,
	groupByIp,
	percents,
	PERIODS,
	select as selectAlerts,
	valueOf,
	withFilter,
	withView,
	type Bucket,
	type Dim,
	type ExplorerView,
	type FilterKey,
	type IpGroup,
	type PeriodKey,
	type Range,
} from "../explorer/model.js";
import type { ActionElement } from "@emdash-cms/blocks/server";

import {
	actions,
	banner,
	button,
	CHART_COLOURS,
	columns,
	confirmDialog,
	context,
	dailyChart,
	empty,
	fields,
	form,
	header,
	link,
	menu,
	section,
	select,
	table,
	textInput,
	type SecurityBlock,
} from "./blocks.js";
import { countryName, engineLabel, formatCompact, formatCount, formatHour, formatRemaining, formatShortDay } from "./format.js";
import { DECISIONS_PATH, SECURITY_PATH } from "./ids.js";
import { seriesLine } from "./security.js";
import { banForm, reviewBlocks } from "./decisions.js";

export const EXPLORER = "cs:x";
export const GROUP_ROWS = 20;
export const ALERT_ROWS = 25;
/** Log queries a page may make: about 400 rows, more than a year of merged days. */
export const LOG_PAGES = 4;

/** The explorer's write controls, by the role in their action id. */
export const X_BAN_REVIEW = `${EXPLORER}:banreview`;
export const X_BAN_CONFIRM = `${EXPLORER}:banok`;
export const X_UNBAN = `${EXPLORER}:unban`;
export const X_DELETE = `${EXPLORER}:del`;

/** An action id: the explorer's prefix, the control's role, and the view it leads to. */
export function xid(role: string, view: ExplorerView): string {
	return `${EXPLORER}:${role}|${encodeView(view)}`;
}

export interface ExplorerData {
	/** Every alert of the period, before the kind and the filters. */
	period: LogAlert[];
	/** Addresses with alerts on days before the period, from the day rows' top lists. */
	seenBefore: Set<string>;
	/** True when the log had more rows than a page may read. */
	partial: boolean;
	/** True when the log was not read this time (a write used the calls). */
	skipped: boolean;
}

/**
 * The period's alerts and the addresses seen before it.
 * Calls: the day rows before the period (one), and up to `calls - 1` log queries, `LOG_PAGES` at most.
 */
export async function loadExplorer(ctx: PluginContext, range: Range, zone: string, calls: number): Promise<ExplorerData> {
	if (calls < 2) return { period: [], seenBefore: new Set(), partial: false, skipped: true };
	const fromDay = localDay(range.since, zone);
	const toDay = localDay(Math.max(range.since, range.until - 1), zone);
	const seenBefore = new Set<string>();
	const days = daysStore(ctx);
	if (days) {
		const page = await days.query({ where: { date: { lt: fromDay } }, orderBy: { date: "desc" }, limit: BIND_LIMIT });
		for (const item of page.items) for (const ip of Object.keys(item.data.ips ?? {})) seenBefore.add(ip);
	}
	const rows: LogRow[] = [];
	let partial = false;
	const log = logStore(ctx);
	let cursor: string | undefined;
	for (let i = 0; log && i < Math.min(LOG_PAGES, calls - 1); i++) {
		const page = await log.query({
			where: { day: { gte: fromDay, lte: toDay } },
			orderBy: { day: "desc" },
			limit: BIND_LIMIT,
			...(cursor ? { cursor } : {}),
		});
		rows.push(...page.items.map((item) => item.data));
		partial = page.hasMore && Boolean(page.cursor);
		if (!partial) break;
		cursor = page.cursor;
	}
	return { period: flatten(rows).filter((a) => a.t >= range.since && a.t < range.until), seenBefore, partial, skipped: false };
}

export interface ExplorerInput {
	view: ExplorerView;
	range: Range;
	data: ExplorerData;
	retentionDays: number;
	/** True when the viewer has a visit before this one. */
	hasVisit: boolean;
	zone: string;
	now: Date;
	lang: Lang;
	/** "live" or "demo" when the viewer gets the write controls. */
	writes: "live" | "demo" | null;
	/** A reviewed ban, waiting for its confirmation. */
	review?: { check: BanCheck; input: BanInput; blocklisted?: boolean };
	/** The live alert for the detail view, or the reason it could not be read. */
	detail?: { alert: RawAlert | null; error?: string };
	/** The Engine names setting: display names by `machine_id`. */
	engineNames?: Record<string, string>;
}

const DIM_LABEL: Record<Dim, MessageKey> = {
	ip: "dimIp",
	behaviour: "dimBehaviour",
	country: "colCountry",
	as: "colAsName",
	scenario: "colScenario",
	path: "dimPath",
	kind: "colKind",
	engine: "dimEngine",
};
const KIND_LABEL: Record<Kind, MessageKey> = { waf: "kindWaf", bot: "kindBot", behaviour: "kindBehaviour", manual: "kindManual" };
export const BEHAVIOUR_LABEL: Record<Behaviour, MessageKey> = {
	"http-exploit": "bhExploit",
	"http-scan": "bhScan",
	"http-crawl": "bhCrawl",
	bot: "bhBot",
	"ssh-bf": "bhSsh",
	manual: "bhManual",
	generic: "bhGeneric",
};
const PERIOD_LABEL: Record<PeriodKey, MessageKey> = {
	"1h": "period1h",
	"24h": "period24h",
	"3d": "period3d",
	"7d": "period7d",
	"30d": "period30d",
	ret: "periodRet",
	visit: "periodVisit",
};
const FILTER_LABEL: Record<FilterKey, MessageKey> = { ip: "dimIp", cn: "colCountry", sc: "colScenario", bh: "dimBehaviour", as: "colAsName", tg: "dimPath", en: "dimEngine" };
const DIM_OF_FILTER: Record<FilterKey, Dim> = { ip: "ip", cn: "country", sc: "scenario", bh: "behaviour", as: "as", tg: "path", en: "engine" };

/** An engine in full, for the detail view: its name and its whole machine id. */
function engineFull(id: string, names: Record<string, string> | undefined, lang: Lang): string {
	if (!id) return t(lang, "unknown");
	return names?.[id] ? `${names[id]} (${id})` : id;
}

/** A dimension's value as people read it: a country's name, a behaviour's label, an engine's name. */
export function labelOf(dim: Dim, value: string, lang: Lang, names?: Record<string, string>): string {
	if (dim === "engine") return engineLabel(value, names, lang);
	if (!value) return t(lang, "unknown");
	if (dim === "country") return countryName(lang)(value);
	if (dim === "behaviour") return t(lang, BEHAVIOUR_LABEL[value as Behaviour] ?? "bhGeneric");
	if (dim === "kind") return t(lang, KIND_LABEL[value as Kind] ?? "kindBehaviour");
	return value;
}

/** Long values cut for a table cell, so a column stays narrow. */
function clip(value: string, max = 40): string {
	return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/** A scenario without its vendor prefix, which every hub scenario shares. */
function shortScenario(scenario: string): string {
	return scenario.replace(/^crowdsecurity\//, "");
}

function bucketLabel(bucket: Bucket, range: Range, zone: string, lang: Lang): string {
	if (range.bucket === "day") return formatShortDay(localDay(bucket.start, zone), lang);
	if (range.bucket === "5m") {
		return new Intl.DateTimeFormat("en-AU", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: zone }).format(bucket.start);
	}
	const hour = formatHour(bucket.start, zone);
	return range.until - range.since > 26 * 3_600_000 ? `${formatShortDay(localDay(bucket.start, zone), lang)} ${hour}` : hour;
}


function spanText(ms: number, lang: Lang): string {
	return ms < 60_000 ? t(lang, "spanUnderMinute") : formatRemaining(ms / 1000, lang);
}

export function renderExplorer(input: ExplorerInput): SecurityBlock[] {
	const { view, lang } = input;
	if (view.al) return detailBlocks(input);
	const out: SecurityBlock[] = [...periodBar(input), kindTabs(input)];
	if (input.data.skipped) {
		if (view.d) out.push(...addressHeader(input, undefined), ...writeBlocks(input, false));
		out.push(empty({ title: t(lang, "explorerNotRead"), description: t(lang, "decisionsNotReadDetail") }));
		return out;
	}
	const kindOnly = selectAlerts(input.data.period, { ...view, f: {}, d: undefined }, input.range);
	const selected = selectAlerts(input.data.period, view, input.range);
	out.push(...filterBlocks(input, kindOnly, selected));
	if (input.data.partial) out.push(banner({ description: t(lang, "explorerPartial"), variant: "alert" }));
	if (view.d) return [...out, ...addressBlocks(input, selected)];

	const buckets = bucketsOf(input.range, input.zone);
	out.push(columns([panel(input, selected, buckets, 0), panel(input, selected, buckets, 1)], { blockId: "cs:x:panels" }));
	out.push(
		actions(
			[
				button(xid("grp:ip", withView(view, { g: true })), t(lang, "groupByIp"), { style: view.g ? "primary" : "secondary" }),
				button(xid("grp:each", withView(view, { g: false })), t(lang, "eachAlert"), { style: view.g ? "secondary" : "primary" }),
			],
			{ blockId: "cs:x:grouping" },
		),
	);
	out.push(...(view.g ? groupTable(input, selected) : alertTable(input, selected, "cs:x:alerts")));
	return out;
}

function periodBar(input: ExplorerInput): SecurityBlock[] {
	const { view, lang, range, zone, now } = input;
	const periods = PERIODS.filter((p) => p !== "visit" || input.hasVisit);
	const elements: ActionElement[] = periods.map((p) =>
		button(xid(`per:${p}`, withView(view, { p, o: 0 })), p === "ret" ? t(lang, "periodRetDays", { days: input.retentionDays }) : t(lang, PERIOD_LABEL[p]), {
			style: view.p === p ? "primary" : "secondary",
		}),
	);
	if (range.steps) {
		elements.push(button(xid("back", withView(view, { o: view.o + 1 })), "◀", { style: "secondary" }));
		if (view.o > 0) elements.push(button(xid("fwd", withView(view, { o: view.o - 1 })), "▶", { style: "secondary" }));
	}
	elements.push(link(t(lang, "securityPage"), { kind: "plugin-page", path: SECURITY_PATH }, { appearance: "secondary" }));
	elements.push(link(t(lang, "decisionsPage"), { kind: "plugin-page", path: DECISIONS_PATH }, { appearance: "secondary" }));
	return [
		actions(elements, { blockId: "cs:x:periods" }),
		context(t(lang, "periodRange", { from: formatCompact(range.since, lang, zone, now), to: formatCompact(range.until, lang, zone, now) })),
	];
}

function kindTabs(input: ExplorerInput): SecurityBlock {
	const { view, lang } = input;
	return actions(
		[
			button(xid("kind:all", withFilter(view, "k", null)), t(lang, "allKinds"), { style: view.k === null ? "primary" : "secondary" }),
			...KINDS.map((k) => button(xid(`kind:${k}`, withFilter(view, "k", k)), t(lang, KIND_LABEL[k]), { style: view.k === k ? "primary" : "secondary" })),
		],
		{ blockId: "cs:x:kinds" },
	);
}

/** The values of a dimension, most alerts first. */
function valuesOf(alerts: LogAlert[], dim: Dim): string[] {
	const counts = new Map<string, number>();
	for (const a of alerts) {
		const v = valueOf(a, dim);
		if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
	}
	return [...counts.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).map(([v]) => v);
}

/** Up to twelve values of a dimension, most alerts first, as select options. Twelve keeps the page inside the host's node limit. */
function choices(alerts: LogAlert[], dim: Dim, input: ExplorerInput, current?: string): Array<{ label: string; value: string }> {
	const { lang } = input;
	const values = valuesOf(alerts, dim).slice(0, 12);
	if (current && !values.includes(current)) values.unshift(current);
	return [{ label: t(lang, "any"), value: "" }, ...values.map((v) => ({ label: clip(labelOf(dim, v, lang, input.engineNames), 60), value: v }))];
}

/** More than one engine in these alerts: the engine shows then, and a single-host site sees no change. */
function manyEngines(alerts: LogAlert[]): boolean {
	return valuesOf(alerts, "engine").length > 1;
}

function filterBlocks(input: ExplorerInput, kindOnly: LogAlert[], selected: LogAlert[]): SecurityBlock[] {
	const { view, lang } = input;
	const out: SecurityBlock[] = [];
	const active = FILTER_KEYS.filter((key) => view.f[key]);
	if (active.length > 0) {
		out.push(
			actions(
				active.map((key) =>
					button(xid(`rm:${key}`, withFilter(view, key, null)), `${t(lang, FILTER_LABEL[key])}: ${clip(labelOf(DIM_OF_FILTER[key], view.f[key]!, lang, input.engineNames), 30)} ✕`, {
						style: "secondary",
					}),
				),
				{ blockId: "cs:x:chips" },
			),
		);
	}
	out.push(
		form(
			[
				textInput("ip", t(lang, "filterIp"), { placeholder: "203.0.113.7 or 203.0.113.0/24", ...(view.f.ip && { initialValue: view.f.ip }) }),
				select("cn", t(lang, "colCountry"), choices(kindOnly, "country", input, view.f.cn), { initialValue: view.f.cn ?? "" }),
				select("sc", t(lang, "colScenario"), choices(kindOnly, "scenario", input, view.f.sc), { initialValue: view.f.sc ?? "" }),
				select("bh", t(lang, "dimBehaviour"), [{ label: t(lang, "any"), value: "" }, ...BEHAVIOURS.map((b) => ({ label: t(lang, BEHAVIOUR_LABEL[b]), value: b }))], {
					initialValue: view.f.bh ?? "",
				}),
				select("as", t(lang, "colAsName"), choices(kindOnly, "as", input, view.f.as), { initialValue: view.f.as ?? "" }),
				select("tg", t(lang, "dimPath"), choices(kindOnly, "path", input, view.f.tg), { initialValue: view.f.tg ?? "" }),
				...(manyEngines(kindOnly) || view.f.en
					? [select("en", t(lang, "dimEngine"), choices(kindOnly, "engine", input, view.f.en), { initialValue: view.f.en ?? "" })]
					: []),
			],
			{ label: t(lang, "applyFilters"), actionId: xid("filter", view) },
			{ blockId: "cs:x:filters" },
		),
	);
	out.push(context(t(lang, "explorerCount", { count: selected.length, formatted: formatCount(selected.length, lang) })));
	return out;
}

/** The colours of a panel's series: the top three, then Other in teal. */
const PANEL_COLOURS = [0, 1, 2, 4];

function panel(input: ExplorerInput, selected: LogAlert[], buckets: Bucket[], index: 0 | 1): SecurityBlock[] {
	const { view, lang, range, zone } = input;
	const dim = view.b[index];
	const b = breakdown(selected, dim, buckets);
	const key = FILTER_OF[dim];
	const names = [...b.top.map((entry) => clip(labelOf(dim, dim === "scenario" ? shortScenario(entry.value) : entry.value, lang, input.engineNames), 32)), t(lang, "other")];
	const pct = percents([...b.top.map((entry) => entry.alerts), b.other]);
	const rows: Array<Record<string, unknown>> = b.top.map((entry, i) => ({
		value: names[i],
		alerts: entry.alerts,
		share: `${pct[i]}%`,
		add: entry.value ? button(xid(`add:${index}:${i}`, withFilter(view, key, entry.value)), t(lang, "filterBy"), { style: "secondary" }) : null,
	}));
	if (b.other > 0) rows.push({ value: t(lang, "other"), alerts: b.other, share: `${pct[b.top.length]}%`, add: null });
	const series = b.series.map((data, i) => ({ name: i < b.top.length ? names[i]! : t(lang, "other"), data, colour: CHART_COLOURS[PANEL_COLOURS[Math.min(i, 3)]!]! }));
	const shown = series.map((s, i) => ({ name: s.name, colour: PANEL_COLOURS[Math.min(i, 3)]!, drawn: s.data.some((v) => v > 0) })).filter((s) => s.drawn);
	return [
		header(t(lang, DIM_LABEL[dim])),
		table({
			blockId: `cs:x:panel${index}`,
			pageActionId: `cs:x:panel${index}:page`,
			columns: [
				{ key: "value", label: t(lang, DIM_LABEL[dim]), format: "text" },
				{ key: "alerts", label: t(lang, "colAlerts"), format: "number" },
				{ key: "share", label: t(lang, "colShare"), format: "text" },
				{ key: "add", label: "", format: "element" },
			],
			rows,
			emptyText: t(lang, "noAlertsHere"),
		}),
		dailyChart({
			labels: buckets.map((bucket) => bucketLabel(bucket, range, zone, lang)),
			series,
			style: "bar",
			height: 200,
			blockId: `cs:x:hist${index}`,
		}),
		...(shown.length > 0 ? [seriesLine(lang, shown)] : []),
		actions(
			[
				menu(
					xid(`dim${index}`, view),
					t(lang, "changeBreakdown"),
					DIMENSIONS.filter((d) => d !== dim).map((d) => ({ label: t(lang, DIM_LABEL[d]), value: d })),
				),
			],
			{ blockId: `cs:x:dimpick${index}` },
		),
	];
}

/** The view with its period's end fixed, for the table's next page: a rolling period would move on otherwise, and drop or repeat rows. */
function anchored(input: ExplorerInput): ExplorerView {
	return { ...input.view, at: input.view.at ?? input.now.getTime() };
}

function hints(group: Pick<IpGroup, "ip" | "bannedUntil">, input: ExplorerInput): string {
	const { lang, now } = input;
	const parts: string[] = [];
	if (group.bannedUntil && group.bannedUntil > now.getTime()) parts.push(t(lang, "hintBanned"));
	if (input.data.seenBefore.has(group.ip)) parts.push(t(lang, "hintSeenBefore"));
	return parts.join(" · ");
}

function groupTable(input: ExplorerInput, selected: LogAlert[]): SecurityBlock[] {
	const { view, lang, zone, now } = input;
	const groups = groupByIp(selected, now);
	const page = groups.slice(view.n * GROUP_ROWS, (view.n + 1) * GROUP_ROWS);
	const country = countryName(lang);
	const more = (n: number) => (n > 0 ? ` ${t(lang, "plusMore", { count: n })}` : "");
	return [
		table({
			blockId: "cs:x:groups",
			pageActionId: xid("tbl", anchored(input)),
			columns: [
				{ key: "when", label: t(lang, "colWhen"), format: "text" },
				{ key: "source", label: t(lang, "colSource"), format: "text" },
				{ key: "details", label: t(lang, "colDetails"), format: "text" },
				{ key: "target", label: t(lang, "colTarget"), format: "text" },
				{ key: "view", label: "", format: "element" },
			],
			rows: page.map((g) => ({
				when: [
					formatCompact(g.last, lang, zone, now),
					t(lang, "alertsOver", { count: g.alerts, span: spanText(g.last - g.first, lang) }),
					t(lang, "firstSeen", { time: formatCompact(g.first, lang, zone, now) }),
				].join(" · "),
				source: [g.ip, country(g.country), clip(g.asName, 28), hints(g, input)].filter(Boolean).join(" · "),
				details: [
					g.waf === g.alerts ? t(lang, "detectWaf") : g.waf === 0 ? t(lang, "detectLog") : t(lang, "detectBoth"),
					g.scenarios
						.slice(0, 2)
						.map(([s, n]) => `${clip(shortScenario(s), 32)} ×${n}`)
						.join(", ") + more(g.scenarios.length - 2),
					t(lang, "decisionsN", { count: g.decisions }),
					...(g.engines.length > 1 ? [t(lang, "seenByEngines", { count: g.engines.length })] : []),
				].join(" · "),
				target:
					g.paths
						.slice(0, 2)
						.map(([p, n]) => `${clip(p, 28)} ×${n}`)
						.join(", ") + more(g.paths.length - 2),
				view: button(xid(`ipv:${g.ip}`, withView(view, { d: g.ip })), t(lang, "viewAlerts"), { style: "secondary" }),
			})),
			...((view.n + 1) * GROUP_ROWS < groups.length && { nextCursor: String(view.n + 1) }),
			emptyText: t(lang, "noAlertsHere"),
		}),
		context(t(lang, "groupsCount", { count: groups.length, from: groups.length ? view.n * GROUP_ROWS + 1 : 0, to: view.n * GROUP_ROWS + page.length })),
	];
}

function decisionText(a: LogAlert, input: ExplorerInput): string {
	const { now, lang } = input;
	if (a.u && a.u > now.getTime()) return `${a.y ?? ""} ${formatRemaining((a.u - now.getTime()) / 1000, lang)}`.trim();
	return a.y ? t(lang, "decisionEnded", { type: a.y }) : "";
}

function alertTable(input: ExplorerInput, selected: LogAlert[], blockId: string): SecurityBlock[] {
	const { view, lang, zone, now } = input;
	const engines = manyEngines(input.data.period);
	const sorted = [...selected].sort((a, b) => b.t - a.t || b.i - a.i);
	const page = sorted.slice(view.n * ALERT_ROWS, (view.n + 1) * ALERT_ROWS);
	return [
		table({
			blockId,
			pageActionId: xid(`tbl:${blockId}`, anchored(input)),
			columns: [
				{ key: "time", label: t(lang, "colWhen"), format: "text" },
				...(view.d ? [] : [{ key: "ip", label: t(lang, "colSource"), format: "text" as const }]),
				...(engines ? [{ key: "engine", label: t(lang, "dimEngine"), format: "text" as const }] : []),
				{ key: "scenario", label: t(lang, "colScenario"), format: "text" },
				{ key: "path", label: t(lang, "colTarget"), format: "text" },
				{ key: "decision", label: t(lang, "colDecision"), format: "text" },
				{ key: "detail", label: "", format: "element" },
			],
			rows: page.map((a) => ({
				time: formatCompact(a.t, lang, zone, now),
				...(!view.d && { ip: [a.a, a.c].filter(Boolean).join(" · ") }),
				...(engines && { engine: engineLabel(a.m ?? "", input.engineNames, lang) }),
				scenario: `${clip(shortScenario(a.s), 36)} (${t(lang, KIND_LABEL[kindOfLog(a)])})`,
				path: clip(a.p, 32),
				decision: decisionText(a, input),
				detail: button(xid(`al:${a.i}`, withView(view, { al: a.i })), t(lang, "alertDetail"), { style: "secondary" }),
			})),
			...((view.n + 1) * ALERT_ROWS < sorted.length && { nextCursor: String(view.n + 1) }),
			emptyText: t(lang, "noAlertsHere"),
		}),
	];
}

function addressHeader(input: ExplorerInput, group: IpGroup | undefined): SecurityBlock[] {
	const { view, lang, zone, now } = input;
	const out: SecurityBlock[] = [
		actions([button(xid("ipx", withView(view, { d: undefined })), t(lang, "backToExplorer"), { style: "secondary" })], { blockId: "cs:x:ipback" }),
		header(t(lang, "alertsFrom", { ip: view.d ?? "" })),
	];
	if (!group) return out;
	const hint = hints(group, input);
	out.push(
		fields(
			[
				{ label: t(lang, "colCountry"), value: countryName(lang)(group.country) || t(lang, "unknown") },
				{ label: t(lang, "colAsName"), value: group.asName || t(lang, "unknown") },
				{ label: t(lang, "colAlerts"), value: t(lang, "alertsOver", { count: group.alerts, span: spanText(group.last - group.first, lang) }) },
				{ label: t(lang, "firstSeenLabel"), value: formatCompact(group.first, lang, zone, now) },
				{
					label: t(lang, "decisionsActive"),
					value: group.bannedUntil ? t(lang, "bannedFor", { remaining: formatRemaining((group.bannedUntil - now.getTime()) / 1000, lang) }) : t(lang, "none"),
				},
				...(hint ? [{ label: t(lang, "hints"), value: hint }] : []),
			],
			{ blockId: "cs:x:ipfacts" },
		),
	);
	return out;
}

function addressBlocks(input: ExplorerInput, selected: LogAlert[]): SecurityBlock[] {
	const group = groupByIp(selected, input.now)[0];
	const banned = Boolean(group?.bannedUntil && group.bannedUntil > input.now.getTime());
	return [...addressHeader(input, group), ...writeBlocks(input, banned), ...alertTable(input, selected, "cs:x:ipalerts")];
}

/**
 * Ban or Remove ban for the address being looked at, behind the same gates
 * as the CrowdSec decisions page: an administrator, Allow changes on and
 * a LAPI source, or demo data, where they change nothing. A ban is
 * reviewed first, with every check it will pass through.
 */
function writeBlocks(input: ExplorerInput, banned: boolean): SecurityBlock[] {
	const { lang, writes } = input;
	const view: ExplorerView = { ...input.view, n: 0 };
	delete view.al;
	const ip = view.d;
	if (!writes || !ip) return [];
	const out: SecurityBlock[] = [];
	if (writes === "demo") out.push(context(t(lang, "demoWrites")));
	if (input.review) return [...out, ...reviewBlocks(input.review, lang, xid("banok", view))];
	if (banned) {
		out.push(
			actions(
				[
					button(xid("unban", view), t(lang, "removeBan"), {
						style: "danger",
						confirm: confirmDialog(t(lang, "removeTitle"), t(lang, "removeBanText", { value: ip }), t(lang, "remove"), t(lang, "cancel")),
					}),
				],
				{ blockId: "cs:x:unban" },
			),
		);
		return out;
	}
	out.push(banForm(lang, xid("banreview", view), ip));
	return out;
}

/** Can an alert be deleted: every decision ended more than the grace period ago? */
function deletableNow(alert: RawAlert): boolean {
	return (alert.decisions ?? []).every((d) => {
		const left = parseGoDuration(d.duration);
		return left !== null && left <= -DELETE_GRACE_S;
	});
}

/** Meta and decision rows an alert's detail shows: an alert with thousands would pass the host's node limit. */
export const DETAIL_ROWS = 20;

/** The live detail of one alert, from `GET /v1/alerts/{id}`. */
function detailBlocks(input: ExplorerInput): SecurityBlock[] {
	const { view, lang, zone, now } = input;
	const out: SecurityBlock[] = [
		actions([button(xid("alx", withView(view, { al: undefined })), t(lang, "backToAlerts"), { style: "secondary" })], { blockId: "cs:x:alback" }),
	];
	const alert = input.detail?.alert;
	if (!alert) {
		out.push(banner({ description: input.detail?.error ?? t(lang, "alertGone", { id: view.al ?? 0 }), variant: "error" }));
		return out;
	}
	const ip = alert.source?.value || alert.source?.ip || "";
	out.push(header(t(lang, "alertTitle", { id: alert.id ?? view.al ?? 0, scenario: alert.scenario ?? "" })));
	out.push(
		fields(
			[
				{ label: t(lang, "colAddress"), value: ip || t(lang, "unknown") },
				{ label: t(lang, "colCountry"), value: countryName(lang)(alert.source?.cn ?? "") || t(lang, "unknown") },
				{ label: t(lang, "colAsName"), value: alert.source?.as_name || t(lang, "unknown") },
				{ label: t(lang, "colKind"), value: alert.kind ?? "" },
				{ label: t(lang, "dimEngine"), value: engineFull(alert.machine_id ?? "", input.engineNames, lang) },
				{ label: t(lang, "started"), value: alert.start_at ? formatCompact(alert.start_at, lang, zone, now) : "" },
				{ label: t(lang, "eventsCount"), value: String(alert.events_count ?? 0) },
				...(alert.message ? [{ label: t(lang, "message"), value: clip(alert.message, 200) }] : []),
			],
			{ blockId: "cs:x:alfacts" },
		),
	);
	const meta = (alert.meta ?? []).slice(0, DETAIL_ROWS).map((m) => {
		let value = m.value ?? "";
		try {
			const parsed = JSON.parse(value) as unknown;
			if (Array.isArray(parsed)) value = parsed.join(", ");
		} catch {
			// a plain string
		}
		return { key: m.key ?? "", value: clip(value, 200) };
	});
	if (meta.length > 0) {
		out.push(header(t(lang, "alertMeta")));
		out.push(
			table({
				blockId: "cs:x:almeta",
				pageActionId: "cs:x:almeta:page",
				columns: [
					{ key: "key", label: t(lang, "colKey"), format: "text" },
					{ key: "value", label: t(lang, "colValue"), format: "text" },
				],
				rows: meta,
			}),
		);
	}
	const events = (alert.events ?? []).slice(0, 10).map((event) => {
		const get = (...keys: string[]) => keys.map((k) => event.meta?.find((m) => m.key === k)?.value).find(Boolean) ?? "";
		return {
			time: event.timestamp ? formatCompact(event.timestamp, lang, zone, now) : "",
			uri: clip(get("target_uri", "uri", "http_path"), 60),
			agent: clip(get("http_user_agent", "user_agent"), 60),
			rule: clip(get("rule_name"), 40),
		};
	});
	if (events.length > 0) {
		out.push(header(t(lang, "alertEvents", { count: events.length, total: alert.events?.length ?? 0 })));
		out.push(
			table({
				blockId: "cs:x:alevents",
				pageActionId: "cs:x:alevents:page",
				columns: [
					{ key: "time", label: t(lang, "colWhen"), format: "text" },
					{ key: "uri", label: t(lang, "colTarget"), format: "text" },
					{ key: "agent", label: t(lang, "colUserAgent"), format: "text" },
					{ key: "rule", label: t(lang, "colRule"), format: "text" },
				],
				rows: events,
			}),
		);
	}
	const all = alert.decisions ?? [];
	const active = all.some((d) => (parseGoDuration(d.duration) ?? 0) > 0);
	const decisions = all.slice(0, DETAIL_ROWS).map((d) => {
		const left = parseGoDuration(d.duration);
		return {
			type: d.type ?? "",
			value: d.value ?? "",
			origin: d.origin ?? "",
			remaining: left === null ? (d.duration ?? "") : left > 0 ? formatRemaining(left, lang) : t(lang, "ended"),
		};
	});
	out.push(header(t(lang, "colDecisions")));
	out.push(
		table({
			blockId: "cs:x:aldecisions",
			pageActionId: "cs:x:aldecisions:page",
			columns: [
				{ key: "type", label: t(lang, "colType"), format: "badge" },
				{ key: "value", label: t(lang, "colAddress"), format: "text" },
				{ key: "origin", label: t(lang, "colOrigin"), format: "text" },
				{ key: "remaining", label: t(lang, "colRemaining"), format: "text" },
			],
			rows: decisions,
			emptyText: t(lang, "noDecisionsOnAlert"),
		}),
	);
	if (all.length > DETAIL_ROWS) out.push(context(t(lang, "andMore", { count: all.length - DETAIL_ROWS })));
	if (input.writes && ip) {
		// The controls lead back to the address's alerts once the change is made.
		const back: ExplorerView = { ...view, d: ip };
		delete back.al;
		out.push(...writeBlocks({ ...input, view: back }, active));
		if (deletableNow(alert)) {
			out.push(
				actions(
					[
						button(xid("del", { ...back, al: alert.id ?? view.al }), t(lang, "delete"), {
							style: "danger",
							confirm: confirmDialog(
								t(lang, "deleteAlertTitle"),
								t(lang, "deleteAlertText", { id: alert.id ?? view.al ?? 0, scenario: alert.scenario ?? "", ip }),
								t(lang, "delete"),
								t(lang, "cancel"),
							),
						}),
					],
					{ blockId: "cs:x:delete" },
				),
			);
			out.push(context(t(lang, "deleteNote")));
		}
	}
	return out;
}

/** The view an interaction asks for, from the action id and the form or menu it came from. */
export function parseExplorerInput(input: Record<string, unknown>): { view: ExplorerView; base: string } {
	const id = typeof input.action_id === "string" ? input.action_id : "";
	const cut = id.indexOf("|");
	const base = cut < 0 ? id : id.slice(0, cut);
	if (!base.startsWith(`${EXPLORER}:`)) return { view: { ...DEFAULT_VIEW, f: {} }, base: "" };
	let view = cut < 0 ? { ...DEFAULT_VIEW, f: {} } : decodeView(id.slice(cut + 1));
	if ((base === `${EXPLORER}:dim0` || base === `${EXPLORER}:dim1`) && typeof input.value === "string" && (DIMENSIONS as readonly string[]).includes(input.value)) {
		const b: [Dim, Dim] = [...view.b] as [Dim, Dim];
		b[base.endsWith("1") ? 1 : 0] = input.value as Dim;
		view = withView(view, { b });
	}
	if (base === `${EXPLORER}:filter` && typeof input.values === "object" && input.values !== null) {
		const values = input.values as Record<string, unknown>;
		for (const key of FILTER_KEYS) {
			const value = typeof values[key] === "string" ? (values[key] as string).trim() : "";
			view = withFilter(view, key, value || null);
		}
		// What the decoder does not accept (an address that does not parse) is dropped here too.
		view = decodeView(encodeView(view));
	}
	if (base.startsWith(`${EXPLORER}:tbl`)) {
		const value = typeof input.value === "object" && input.value !== null ? (input.value as Record<string, unknown>) : {};
		const n = Number(value.cursor);
		view = { ...view, n: Number.isInteger(n) && n > 0 && n < 10_000 ? n : 0 };
	}
	return { view, base };
}
