/**
 * The dashboard widget, "Security".
 *
 * It reads the sync state only: the hourly buckets the sync keeps for the
 * last 48 hours and the active ban count from its last read. No LAPI
 * request and no storage read happens during a render, because the widget
 * renders on every dashboard visit of every editor.
 */

import { t, type Lang } from "../i18n.js";
import { coveredSince, sumHours, type SyncState } from "../sync/scheduler.js";
import { actions, button, context, empty, link, stats, table, type SecurityBlock } from "./blocks.js";
import { comparisonText, formatAge, formatCount, formatShort, trendOf } from "./format.js";
import { discarded } from "../metrics/sample.js";
import type { TrafficDay } from "../store/rows.js";
import { addDays, daysBetween, localDay } from "../sync/time.js";
import { SECURITY_PATH, WIDGET_REFRESH } from "./ids.js";
import { emptyReason, statusLine } from "./status.js";
import { ranked } from "../store/rows.js";

const HOUR_MS = 3_600_000;

export interface WidgetInput {
	state: SyncState;
	zone: string;
	now: Date;
	lang: Lang;
	/** Traffic days for this week and the one before, when the traffic charts are on. */
	traffic?: TrafficDay[];
	/** When metrics sampling started, for the weekly comparison. */
	sampledSince?: string;
}

export function renderWidget({ state, zone, now, lang, traffic, sampledSince }: WidgetInput): SecurityBlock[] {
	const nowMs = now.getTime();
	const current = sumHours(state, nowMs - 24 * HOUR_MS, nowMs + HOUR_MS);
	const previous = sumHours(state, nowMs - 48 * HOUR_MS, nowMs - 24 * HOUR_MS);

	if (!state.lastSync && current.alerts === 0) {
		return [empty({ title: t(lang, "m0"), description: emptyReason(state, lang) }), controls(lang)];
	}

	// A previous day the store does not fully reach is "no history yet",
	// which must not read as a fall in attacks.
	const covered = coveredSince(state);
	const hasPrevious = covered !== null && Date.parse(covered) <= nowMs - 48 * HOUR_MS;
	const before = hasPrevious ? previous.alerts : null;
	const trend = trendOf(current.alerts, before);

	const active = state.active;
	const out: SecurityBlock[] = [
		stats([
			{
				label: t(lang, "alerts24h"),
				value: formatCount(current.alerts, lang),
				description: comparisonText(current.alerts, before, lang),
				...(trend && { trend }),
			},
			{
				label: t(lang, "md"),
				value: active ? `${formatCount(active.bans, lang)}${active.truncated ? "+" : ""}` : "-",
				description: active ? t(lang, "me", { age: formatAge(active.at, now, lang) ?? "" }) : t(lang, "mf"),
			},
		]),
		stats([
			{ label: t(lang, "m9"), value: formatCount(current.waf, lang) },
			{ label: t(lang, "ma"), value: formatCount(current.bot, lang) },
			{ label: t(lang, "mb"), value: formatCount(current.behaviour, lang) },
		]),
	];

	if (traffic) {
		// Seven local days, today included, against the seven before.
		const today = localDay(now, zone);
		const sum = (from: number, to: number) =>
			traffic
				.filter((d) => daysBetween(addDays(today, -to), d.date) >= 0 && daysBetween(d.date, addDays(today, -from)) >= 0)
				.reduce((n, d) => n + discarded(d.counters, "packets").total, 0);
		const week = sum(0, 6);
		const before = sampledSince && localDay(sampledSince, zone) <= addDays(today, -13) ? sum(7, 13) : null;
		const weekTrend = trendOf(week, before);
		out.push(
			stats([
				{
					label: t(lang, "m28"),
					value: t(lang, "m29", { count: formatShort(week, lang) }),
					description: comparisonText(week, before, lang),
					...(weekTrend && { trend: weekTrend }),
				},
			]),
		);
	}

	const top = ranked(current.scenarios).slice(0, 3);
	if (top.length > 0) {
		out.push(
			table({
				blockId: "cs:widget:scenarios",
				pageActionId: "cs:widget:scenarios:page",
				columns: [
					{ key: "scenario", label: t(lang, "mg"), format: "code" },
					{ key: "alerts", label: t(lang, "mh"), format: "number" },
				],
				rows: top.map(([scenario, alerts]) => ({ scenario, alerts })),
			}),
		);
	}

	out.push(context(statusLine(state, now, lang, zone)));
	out.push(controls(lang));
	return out;
}

function controls(lang: Lang) {
	return actions([
		button(WIDGET_REFRESH, t(lang, "refresh"), { style: "secondary" }),
		link(t(lang, "m4"), { kind: "plugin-page", path: SECURITY_PATH }, { appearance: "secondary" }),
	]);
}
