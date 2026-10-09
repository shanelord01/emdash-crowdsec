/**
 * The Decisions page: the active bans, read live from LAPI on each load.
 *
 * One search of alerts with an unexpired decision, `ACTIVE_LIMIT` alerts at
 * most (about 3 MB), then one row per unexpired decision. Sorting by
 * expiry and paging happen in memory: the sort travels in the table's id,
 * the position in its cursor.
 *
 * With changes allowed, an administrator also sees:
 *
 * - a Remove button per row, which deletes that one decision by id after a
 *   confirmation;
 * - what a ban may never cover (the protected set), above the ban form;
 * - the ban form. A form cannot ask for confirmation, so submitting it only
 *   reviews the ban: every rule runs, and the page comes back with a Ban
 *   button whose confirmation names the address, the duration and whether
 *   the caller's own address could be checked. That button runs every rule
 *   again before it asks LAPI.
 */

import { t, type Lang } from "../i18n.js";
import type { RawAlert, Result } from "../lapi/types.js";
import { isBlocklistDecision } from "../lapi/blocklist.js";
import type { Source } from "../sources.js";
import { MIN_BATCH, type BlocklistSnapshot } from "../sync/scheduler.js";
import { displayNetwork, parseNetwork } from "../net/ip.js";
import { hostOf, type DnsCache } from "../net/protect.js";
import type { CrowdSecSettings } from "../settings.js";
import { parseGoDuration } from "../sync/time.js";
import { BAN_DURATIONS, type BanCheck, type BanInput } from "../write/actions.js";
import {
	actions,
	banner,
	button,
	confirmDialog,
	context,
	empty,
	fields,
	form,
	header,
	link,
	section,
	select,
	table,
	textInput,
	type SecurityBlock,
} from "./blocks.js";
import { countryName, formatAge, formatCompact, formatCount, formatRemaining } from "./format.js";
import { ALERTS_PATH, BAN_CONFIRM, BAN_REVIEW, DECISIONS_REFRESH, DECISIONS_REMOVE, DECISIONS_TABLE, SECURITY_PATH } from "./ids.js";

export const DECISION_ROWS = 50;
/** Searches one read may make, each asking for half the last after an answer over 8 MiB. */
const ACTIVE_TRIES = 3;

/**
 * The alerts with an unexpired decision, `batch` at most. An answer over
 * the 8 MiB response cap is asked again for half as many, three times at
 * most. Calls: the login and up to three searches.
 */
export async function readActive(
	source: Source,
	settings: CrowdSecSettings,
	batch: number,
): Promise<Result<{ alerts: RawAlert[]; truncated: boolean; read: number }>> {
	let size = batch;
	let last: Result<RawAlert[]> | null = null;
	for (let i = 0; i < ACTIVE_TRIES; i++) {
		last = await source.alerts({ activeOnly: true, limit: size, simulated: settings.includeSimulated });
		if (last.ok) return { ok: true, value: { alerts: last.value, truncated: last.value.length >= size, read: size } };
		if (last.problem.key !== "tooLarge" || size <= MIN_BATCH) break;
		size = Math.max(MIN_BATCH, Math.floor(size / 2));
	}
	// Every way out of the loop above is a failure.
	return last as Extract<Result<RawAlert[]>, { ok: false }>;
}

export interface DecisionRow {
	id: number;
	value: string;
	scenario: string;
	type: string;
	origin: string;
	/** Seconds left when read. */
	remaining: number;
	expires: string;
	country: string;
	asName: string;
}

export interface DecisionsView {
	dir: "asc" | "desc";
	offset: number;
}

export const DEFAULT_DECISIONS_VIEW: DecisionsView = { dir: "asc", offset: 0 };

/**
 * One row per unexpired decision of the site's own, soonest to expire first
 * unless asked otherwise. Community blocklist and list decisions are never
 * rows: the page shows them as one count.
 */
export function decisionRows(alerts: RawAlert[], now: Date): DecisionRow[] {
	const rows: DecisionRow[] = [];
	const seen = new Set<number>();
	for (const alert of alerts) {
		for (const decision of alert.decisions ?? []) {
			if (isBlocklistDecision(decision)) continue;
			const left = parseGoDuration(decision.duration);
			if (left === null || left <= 0 || typeof decision.id !== "number" || seen.has(decision.id)) continue;
			seen.add(decision.id);
			rows.push({
				id: decision.id,
				value: decision.value ?? alert.source?.value ?? "",
				scenario: decision.scenario ?? alert.scenario ?? "",
				type: decision.type ?? "",
				origin: decision.origin ?? "",
				remaining: left,
				expires: new Date(now.getTime() + left * 1000).toISOString(),
				country: (alert.source?.cn ?? "").toUpperCase(),
				asName: alert.source?.as_name ?? "",
			});
		}
	}
	return rows;
}

export function parseDecisionsView(input: Record<string, unknown>): DecisionsView {
	const id = typeof input.action_id === "string" ? input.action_id : "";
	const dir = id.split("|")[1] === "desc" ? "desc" : "asc";
	if (!id.startsWith(DECISIONS_TABLE)) return { dir, offset: 0 };
	const value = typeof input.value === "object" && input.value !== null ? (input.value as Record<string, unknown>) : {};
	const sort = value.sort as { key?: unknown; dir?: unknown } | undefined;
	const offset = Number(typeof value.cursor === "string" ? value.cursor : 0);
	return {
		dir: sort?.key === "expires" ? (sort.dir === "desc" ? "desc" : "asc") : dir,
		offset: sort ? 0 : Number.isInteger(offset) && offset > 0 ? offset : 0,
	};
}

/** What a ban may never cover, as the page shows it. */
export interface ProtectedView {
	callers: string[];
	site: string[];
	lapi: string[];
	setting: string[];
	invalidSetting: string[];
	/** False when the site's or LAPI's names have not been looked up yet. */
	dnsKnown: boolean;
}

export function protectedView(opts: { callers: string[]; siteUrl: string; settings: CrowdSecSettings; dns: DnsCache | null }): ProtectedView {
	const addressesOf = (url: string) => {
		const host = hostOf(url);
		if (!host) return [];
		if (parseNetwork(host)) return [host];
		return opts.dns?.addresses[host] ?? [];
	};
	const site = addressesOf(opts.siteUrl);
	const lapi = addressesOf(opts.settings.lapiUrl);
	const named = [hostOf(opts.siteUrl), hostOf(opts.settings.lapiUrl)].filter((h): h is string => Boolean(h && !parseNetwork(h)));
	return {
		callers: opts.callers,
		site,
		lapi,
		setting: opts.settings.protectedAddresses.map(displayNetwork),
		invalidSetting: opts.settings.protectedInvalid,
		dnsKnown: named.every((h) => Boolean(opts.dns?.addresses[h])),
	};
}

export interface DecisionsInput {
	/** Null when the list was not read this time (the invocation had no calls left for it). */
	rows: DecisionRow[] | null;
	truncated: boolean;
	/** How many alerts the read asked for. */
	read: number;
	error?: string;
	view: DecisionsView;
	canWrite: boolean;
	protectedSet?: ProtectedView;
	/** A reviewed ban, waiting for its confirmation. `blocklisted` when the community blocklist already holds the address. */
	review?: { check: BanCheck; input: BanInput; blocklisted?: boolean };
	/** The community blocklist count from its daily task. */
	blocklist?: BlocklistSnapshot | null;
	zone: string;
	now: Date;
	lang: Lang;
}

export function renderDecisions(input: DecisionsInput): SecurityBlock[] {
	const { lang, view } = input;
	const out: SecurityBlock[] = [
		actions(
			[
				button(`${DECISIONS_REFRESH}|${view.dir}`, t(lang, "refresh"), { style: "secondary" }),
				link(t(lang, "securityPage"), { kind: "plugin-page", path: SECURITY_PATH }, { appearance: "secondary" }),
				link(t(lang, "alertsPage"), { kind: "plugin-page", path: ALERTS_PATH }, { appearance: "secondary" }),
			],
			{ blockId: "cs:decisions:controls" },
		),
	];

	if (input.review) out.push(...reviewBlocks(input.review, lang));

	if (input.blocklist) {
		const age = formatAge(input.blocklist.at, input.now, lang) ?? "";
		out.push(
			context(
				input.blocklist.addresses === null
					? t(lang, "blocklistTooMany", { age })
					: t(lang, "blocklistCount", { count: input.blocklist.addresses, formatted: formatCount(input.blocklist.addresses, lang), age }),
				{ blockId: "cs:decisions:blocklist" },
			),
		);
	}

	if (input.error) {
		out.push(banner({ description: input.error, variant: "error" }));
	} else if (input.rows === null) {
		out.push(empty({ title: t(lang, "decisionsNotRead"), description: t(lang, "decisionsNotReadDetail") }));
	} else {
		out.push(...decisionTable(input.rows, input, lang));
	}

	if (input.canWrite && input.protectedSet) out.push(...banBlocks(input.protectedSet, lang));
	return out;
}

function decisionTable(all: DecisionRow[], input: DecisionsInput, lang: Lang): SecurityBlock[] {
	const { view } = input;
	const sorted = [...all].sort((a, b) => (view.dir === "asc" ? a.remaining - b.remaining : b.remaining - a.remaining) || a.id - b.id);
	const rows = sorted.slice(view.offset, view.offset + DECISION_ROWS);
	const end = view.offset + rows.length;
	const country = countryName(lang);
	const bans = new Set(all.filter((row) => row.type.toLowerCase() === "ban").map((row) => row.value)).size;

	const notes = [t(lang, "decisionsCount", { count: all.length, bans })];
	if (input.truncated) notes.push(t(lang, "decisionsTruncated", { count: input.read }));
	if (view.offset > 0 || end < sorted.length) notes.push(t(lang, "showingRows", { from: view.offset + 1, to: end }));
	return [
		context(notes.join(" · ")),
		table({
			blockId: "cs:decisions:table",
			pageActionId: `${DECISIONS_TABLE}|${view.dir}`,
			columns: [
				{ key: "value", label: t(lang, "colAddress"), format: "code" },
				{ key: "scenario", label: t(lang, "colScenario"), format: "text" },
				{ key: "type", label: t(lang, "colType"), format: "badge" },
				{ key: "origin", label: t(lang, "colOrigin"), format: "text" },
				{ key: "expires", label: t(lang, "colRemaining"), format: "text", sortable: true },
				{ key: "network", label: t(lang, "colNetwork"), format: "text" },
				...(input.canWrite ? [{ key: "remove", label: "", format: "element" as const }] : []),
			],
			rows: rows.map((row) => ({
				value: row.value,
				scenario: row.scenario,
				type: row.type,
				origin: row.origin,
				expires: `${formatRemaining(row.remaining, lang)} (${formatCompact(row.expires, lang, input.zone, input.now)})`,
				network: [country(row.country), row.asName].filter(Boolean).join(" · "),
				...(input.canWrite && {
					// Every button an action id of its own: the row's decision id rides in it too.
					remove: button(`${DECISIONS_REMOVE}|${view.dir}|${row.id}`, t(lang, "remove"), {
						style: "danger",
						value: row.id,
						confirm: confirmDialog(
							t(lang, "removeTitle"),
							t(lang, "removeText", { type: row.type, value: row.value }),
							t(lang, "remove"),
							t(lang, "cancel"),
						),
					}),
				}),
			})),
			...(end < sorted.length && { nextCursor: String(end) }),
			emptyText: t(lang, "noActiveDecisions"),
		}),
	];
}

function banBlocks(p: ProtectedView, lang: Lang): SecurityBlock[] {
	const list = (items: string[]) => (items.length > 0 ? items.join(", ") : t(lang, "none"));
	return [
		header(t(lang, "banTitle")),
		fields(
			[
				{ label: t(lang, "protectedCaller"), value: p.callers.length > 0 ? list(p.callers) : t(lang, "callerUnknown") },
				{ label: t(lang, "protectedSite"), value: p.dnsKnown || p.site.length > 0 ? list(p.site) : t(lang, "notLookedUp") },
				{ label: t(lang, "protectedLapi"), value: p.dnsKnown || p.lapi.length > 0 ? list(p.lapi) : t(lang, "notLookedUp") },
				{ label: t(lang, "protectedSetting"), value: list(p.setting) },
			],
			{ blockId: "cs:ban:protected" },
		),
		context(
			[t(lang, "protectedBuiltIn"), ...(p.invalidSetting.length > 0 ? [t(lang, "protectedInvalid", { entries: p.invalidSetting.join(", ") })] : [])].join(" "),
		),
		banForm(lang, BAN_REVIEW),
	];
}

/** The ban form: the address, unless it is already known, the duration, the type and a note. */
export function banForm(lang: Lang, actionId: string, address?: string): SecurityBlock {
	return form(
		[
			...(address ? [] : [textInput("value", t(lang, "fieldAddress"), { placeholder: "203.0.113.7" })]),
			select(
				"duration",
				t(lang, "fieldDuration"),
				Object.keys(BAN_DURATIONS).map((value) => ({ value, label: t(lang, `duration_${value}` as "duration_4h") })),
				{ initialValue: "4h" },
			),
			select(
				"type",
				t(lang, "fieldType"),
				[
					{ value: "ban", label: t(lang, "typeBan") },
					{ value: "captcha", label: t(lang, "typeCaptcha") },
				],
				{ initialValue: "ban" },
			),
			textInput("note", t(lang, "fieldNote"), { placeholder: t(lang, "fieldNoteHint") }),
		],
		{ label: address ? t(lang, "reviewBanOf", { value: address }) : t(lang, "reviewBan"), actionId },
		{ blockId: address ? "cs:x:ban" : "cs:ban:form" },
	);
}

/** A reviewed ban and its confirmed Ban button. */
export function reviewBlocks(review: { check: BanCheck; input: BanInput; blocklisted?: boolean }, lang: Lang, confirmId: string = BAN_CONFIRM): SecurityBlock[] {
	const { check, input } = review;
	const what = t(lang, "reviewWhat", {
		type: input.type === "captcha" ? t(lang, "typeCaptcha") : t(lang, "typeBan"),
		value: check.value,
		duration: t(lang, `duration_${input.duration}` as "duration_4h"),
	});
	const own = [check.ownChecked ? t(lang, "ownChecked") : t(lang, "ownNotChecked"), ...(review.blocklisted ? [t(lang, "alreadyBlocklisted")] : [])].join(" ");
	return [
		banner({ title: t(lang, "reviewTitle"), description: `${what} ${own}`, variant: check.ownChecked ? "default" : "alert" }),
		section(t(lang, "reviewChecks"), {
			accessory: button(confirmId, t(lang, "banNow"), {
				style: "danger",
				value: { value: check.value, duration: input.duration, type: input.type, note: input.note },
				confirm: confirmDialog(t(lang, "banConfirmTitle"), `${what} ${own}`, t(lang, "banNow"), t(lang, "cancel")),
			}),
			blockId: confirmId === BAN_CONFIRM ? "cs:ban:review" : "cs:x:review",
		}),
	];
}
