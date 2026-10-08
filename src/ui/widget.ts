/**
 * The dashboard widget, "Security".
 *
 * It reads the sync state only: the hourly buckets the sync keeps for the
 * last 48 hours and the active ban count from its last read. No LAPI
 * request and no storage read happens during a render, because the widget
 * renders on every dashboard visit of every editor.
 */

import { t, type Lang } from "../i18n.js";
import type { SourceId } from "../settings.js";
import { coveredSince, sumHours, type SyncState } from "../sync/scheduler.js";
import { actions, button, context, empty, link, stats, table, type SecurityBlock } from "./blocks.js";
import { comparisonText, formatAge, formatCount, trendOf } from "./format.js";
import { SECURITY_PATH, WIDGET_REFRESH } from "./ids.js";
import { emptyReason, statusLine } from "./status.js";
import { ranked } from "../store/rows.js";

const HOUR_MS = 3_600_000;

export interface WidgetInput {
	state: SyncState;
	source: SourceId;
	zone: string;
	now: Date;
	lang: Lang;
}

export function renderWidget({ state, source, zone, now, lang }: WidgetInput): SecurityBlock[] {
	const nowMs = now.getTime();
	const current = sumHours(state, nowMs - 24 * HOUR_MS, nowMs + HOUR_MS);
	const previous = sumHours(state, nowMs - 48 * HOUR_MS, nowMs - 24 * HOUR_MS);

	if (!state.lastSync && current.alerts === 0) {
		return [empty({ title: t(lang, "noDataYet"), description: emptyReason(state, lang) }), controls(lang)];
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
				label: t(lang, "activeBans"),
				value: active ? `${formatCount(active.bans, lang)}${active.truncated ? "+" : ""}` : "-",
				description: active ? t(lang, "asOf", { age: formatAge(active.at, now, lang) ?? "" }) : t(lang, "notCountedYet"),
			},
		]),
		stats([
			{ label: t(lang, "kindWaf"), value: formatCount(current.waf, lang) },
			{ label: t(lang, "kindBot"), value: formatCount(current.bot, lang) },
			{ label: t(lang, "kindBehaviour"), value: formatCount(current.behaviour, lang) },
		]),
	];

	const top = ranked(current.scenarios).slice(0, 3);
	if (top.length > 0) {
		out.push(
			table({
				blockId: "cs:widget:scenarios",
				pageActionId: "cs:widget:scenarios:page",
				columns: [
					{ key: "scenario", label: t(lang, "colTopScenarios"), format: "code" },
					{ key: "alerts", label: t(lang, "colAlerts"), format: "number" },
				],
				rows: top.map(([scenario, alerts]) => ({ scenario, alerts })),
			}),
		);
	}

	out.push(context(statusLine(state, source, now, lang, zone)));
	out.push(controls(lang));
	return out;
}

function controls(lang: Lang) {
	return actions([
		button(WIDGET_REFRESH, t(lang, "refresh"), { style: "secondary" }),
		link(t(lang, "openSecurity"), { kind: "plugin-page", path: SECURITY_PATH }, { appearance: "secondary" }),
	]);
}
