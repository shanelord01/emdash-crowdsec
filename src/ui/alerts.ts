/**
 * The Alerts page: stored alerts, newest first, 25 to a page, filtered by
 * kind and scenario.
 *
 * Block Kit keeps no state between interactions. The filter travels in
 * every control's `action_id` after a `|`, and the position in the table's
 * cursor: the table's "Load more" sends only `{ cursor }`, so the rest has
 * to be in its id. "Load more" replaces the table with the next page.
 *
 * With changes allowed, an administrator sees a Delete button on alerts
 * whose decisions ended more than two minutes ago (see
 * `src/write/actions.ts` for why). The button asks for confirmation, and
 * the check runs again against LAPI before anything is deleted.
 */

import type { PluginContext } from "emdash/plugin";

import { t, type Lang } from "../i18n.js";
import { alertsStore } from "../store/access.js";
import { KINDS, ranked, sumMaps, type AlertRow, type DayRow, type Kind } from "../store/rows.js";
import type { SyncState } from "../sync/scheduler.js";
import type { SourceId } from "../settings.js";
import { DELETE_GRACE_S } from "../write/actions.js";
import { actions, button, confirmDialog, context, link, menu, table, type SecurityBlock } from "./blocks.js";
import { countryName, formatTime } from "./format.js";
import { ALERTS_DELETE, ALERTS_SCENARIO, ALERTS_TABLE, ALERTS_VIEW, DECISIONS_PATH, SECURITY_PATH } from "./ids.js";
import { statusLine } from "./status.js";

export const ALERT_ROWS = 25;
const SCENARIO_CHOICES = 20;

export interface AlertsView {
	kind: Kind | null;
	scenario: string | null;
	/** Rows before this table page. */
	offset: number;
	cursor?: string;
}

export const DEFAULT_ALERTS_VIEW: AlertsView = { kind: null, scenario: null, offset: 0 };

export function encodeView(view: AlertsView): string {
	return [view.kind ?? "", view.scenario ?? ""].map(encodeURIComponent).join("|");
}

function decodeOnce(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return "";
	}
}

export function decodeView(encoded: string): AlertsView {
	const [kind, scenario] = encoded.split("|").map(decodeOnce);
	return {
		kind: (KINDS as readonly string[]).includes(kind ?? "") ? (kind as Kind) : null,
		scenario: scenario && scenario.length <= 200 ? scenario : null,
		offset: 0,
	};
}

/** The view and the action an interaction asks for. */
export function parseAlertsInput(input: Record<string, unknown>): { view: AlertsView; deleteId?: unknown } {
	const id = typeof input.action_id === "string" ? input.action_id : "";
	if (input.type !== "block_action" || !id) return { view: DEFAULT_ALERTS_VIEW };
	const cut = id.indexOf("|");
	const base = cut < 0 ? id : id.slice(0, cut);
	const view = decodeView(cut < 0 ? "" : id.slice(cut + 1));

	if (base === ALERTS_VIEW) return { view };
	if (base === ALERTS_SCENARIO) {
		const scenario = typeof input.value === "string" && input.value ? input.value.slice(0, 200) : null;
		return { view: { ...view, scenario } };
	}
	if (base === ALERTS_DELETE) return { view, deleteId: input.value };
	if (base === ALERTS_TABLE) {
		const value = typeof input.value === "object" && input.value !== null ? (input.value as Record<string, unknown>) : {};
		const raw = typeof value.cursor === "string" ? value.cursor : "";
		const sep = raw.indexOf("~");
		const offset = Number(sep < 0 ? raw : raw.slice(0, sep));
		const cursor = sep < 0 ? "" : raw.slice(sep + 1);
		return { view: { ...view, offset: Number.isInteger(offset) && offset > 0 ? offset : 0, ...(cursor && { cursor }) } };
	}
	return { view: DEFAULT_ALERTS_VIEW };
}

export interface AlertsInput {
	view: AlertsView;
	rows: AlertRow[];
	nextCursor?: string;
	/** Scenarios to filter by, from the last 30 days' day rows. */
	scenarios: string[];
	state: SyncState;
	source: SourceId;
	zone: string;
	canDelete: boolean;
	now: Date;
	lang: Lang;
}

/** One page of stored alerts. Calls: one query. */
export async function loadAlerts(ctx: PluginContext, view: AlertsView): Promise<{ rows: AlertRow[]; nextCursor?: string }> {
	const store = alertsStore(ctx);
	if (!store) return { rows: [] };
	const where: Record<string, unknown> = {};
	if (view.kind) where.kind = view.kind;
	if (view.scenario) where.scenario = view.scenario;
	const page = await store.query({
		...(Object.keys(where).length > 0 && { where }),
		orderBy: { startedAt: "desc" },
		limit: ALERT_ROWS,
		...(view.cursor ? { cursor: view.cursor } : {}),
	});
	const rows = page.items.map((item) => item.data);
	return {
		rows,
		...(page.hasMore && page.cursor && { nextCursor: `${view.offset + rows.length}~${page.cursor}` }),
	};
}

export function scenariosOf(days: DayRow[]): string[] {
	return ranked(sumMaps(days.map((d) => d.scenarios)))
		.slice(0, SCENARIO_CHOICES)
		.map(([name]) => name);
}

/** Can this stored alert's Delete button show? Its decisions must have ended more than the grace period ago. */
export function deletable(row: AlertRow, now: Date): boolean {
	return !row.decisionUntil || Date.parse(row.decisionUntil) + DELETE_GRACE_S * 1000 < now.getTime();
}

export function renderAlerts(input: AlertsInput): SecurityBlock[] {
	const { view, lang, now } = input;
	const encoded = encodeView(view);
	const country = countryName(lang);

	const kindLabel: Record<Kind, string> = {
		waf: t(lang, "kindWaf"),
		bot: t(lang, "kindBot"),
		behaviour: t(lang, "kindBehaviour"),
		manual: t(lang, "kindManual"),
	};

	const out: SecurityBlock[] = [
		actions(
			[
				button(`${ALERTS_VIEW}|${encodeView({ ...view, kind: null })}`, t(lang, "allKinds"), { style: view.kind === null ? "primary" : "secondary" }),
				...KINDS.map((kind) =>
					button(`${ALERTS_VIEW}|${encodeView({ ...view, kind })}`, kindLabel[kind], { style: view.kind === kind ? "primary" : "secondary" }),
				),
			],
			{ blockId: "cs:alerts:kinds" },
		),
		actions(
			[
				menu(`${ALERTS_SCENARIO}|${encoded}`, view.scenario ?? t(lang, "allScenarios"), [
					{ label: t(lang, "allScenarios"), value: "" },
					...input.scenarios.map((name) => ({ label: name, value: name })),
				]),
				link(t(lang, "securityPage"), { kind: "plugin-page", path: SECURITY_PATH }, { appearance: "secondary" }),
				link(t(lang, "decisionsPage"), { kind: "plugin-page", path: DECISIONS_PATH }, { appearance: "secondary" }),
			],
			{ blockId: "cs:alerts:filters" },
		),
	];

	const filters = [view.kind ? kindLabel[view.kind] : null, view.scenario].filter(Boolean).join(", ");
	const notes = [filters ? t(lang, "filteredBy", { filters }) : t(lang, "allAlerts")];
	if (view.offset > 0 || input.nextCursor) notes.push(t(lang, "showingRows", { from: view.offset + 1, to: view.offset + input.rows.length }));
	notes.push(statusLine(input.state, input.source, now, lang, input.zone));
	out.push(context(notes.join(" · ")));

	out.push(
		table({
			blockId: "cs:alerts:table",
			pageActionId: `${ALERTS_TABLE}|${encoded}`,
			columns: [
				{ key: "time", label: t(lang, "colTime"), format: "text" },
				{ key: "kind", label: t(lang, "colKind"), format: "badge" },
				{ key: "scenario", label: t(lang, "colScenario"), format: "code" },
				{ key: "ip", label: t(lang, "colAddress"), format: "code" },
				{ key: "country", label: t(lang, "colCountry"), format: "text" },
				{ key: "as", label: t(lang, "colAsName"), format: "text" },
				{ key: "path", label: t(lang, "colPath"), format: "code" },
				{ key: "decision", label: t(lang, "colDecision"), format: "text" },
				...(input.canDelete ? [{ key: "delete", label: "", format: "element" as const }] : []),
			],
			rows: input.rows.map((row) => ({
				time: formatTime(row.startedAt, lang, input.zone),
				kind: kindLabel[row.kind],
				scenario: row.scenario,
				ip: row.ip,
				country: country(row.country),
				as: row.asName,
				path: row.path,
				decision: row.decisionType || "",
				...(input.canDelete && {
					delete: deletable(row, now)
						? button(`${ALERTS_DELETE}|${encoded}|${row.id}`, t(lang, "delete"), {
								style: "danger",
								value: row.id,
								confirm: confirmDialog(
									t(lang, "deleteAlertTitle"),
									t(lang, "deleteAlertText", { id: row.id, scenario: row.scenario, ip: row.ip }),
									t(lang, "delete"),
									t(lang, "cancel"),
								),
							})
						: null,
				}),
			})),
			...(input.nextCursor !== undefined && { nextCursor: input.nextCursor }),
			emptyText: t(lang, "noAlertsHere"),
		}),
	);
	if (input.canDelete) out.push(context(t(lang, "deleteNote")));
	return out;
}
