/**
 * One write asked for from an admin page, shared by the CrowdSec decisions
 * page and the Alerts explorer: the gate, demo data's answer, the ban
 * review, the ban, a decision's removal, an address's bans' removal and an
 * alert's deletion, each with the checks in `./actions.ts`.
 */

import type { PluginContext } from "emdash/plugin";

import { problemText, t, type Lang } from "../i18n.js";
import { isBlocklistDecision } from "../lapi/blocklist.js";
import { sameNetwork } from "../net/ip.js";
import type { CrowdSecSettings, SettingsResult } from "../settings.js";
import type { Source } from "../sources.js";
import type { Loaded } from "../sync/scheduler.js";
import { parseGoDuration } from "../sync/time.js";
import {
	addBan,
	checkAllowlist,
	checkBan,
	deleteAlert,
	LOG_QUERIES,
	parseBanInput,
	removeBansOn,
	removeDecision,
	writeGate,
	writeMode,
	type BanCheck,
	type BanInput,
	type Caller,
	type WriteResult,
} from "./actions.js";

export type Toast = { message: string; type: "success" | "error" };

export type WriteAsk =
	| { kind: "review"; values: Record<string, unknown> }
	| { kind: "ban"; values: Record<string, unknown> }
	| { kind: "decision"; id: unknown }
	| { kind: "unban"; value: string }
	| { kind: "delete"; id: unknown };

export interface WriteOutcome {
	toast?: Toast;
	review?: { check: BanCheck; input: BanInput; blocklisted?: boolean };
	/** True when CrowdSec was changed. */
	wrote: boolean;
	/** Bridge calls the source does not count: a DNS lookup and the alert log's query and write. */
	extra: number;
}

/** Bridge calls a cold DNS lookup spends: two requests per name and the cache write. */
const DNS_CALLS = 5;

export async function runWrite(
	ctx: PluginContext,
	ask: WriteAsk,
	settings: CrowdSecSettings,
	result: SettingsResult,
	loaded: Loaded,
	caller: Caller,
	source: Source | null,
	callsLeft: () => number,
	now: Date,
	lang: Lang,
): Promise<WriteOutcome> {
	const out: WriteOutcome = { wrote: false, extra: 0 };
	const fail = (problem: Parameters<typeof problemText>[1]) => ({ ...out, toast: { message: problemText(lang, problem), type: "error" as const } });
	const mode = writeMode(settings, caller);
	if (!mode) {
		const gate = writeGate(settings, caller);
		return gate.ok ? out : fail(gate.problem);
	}
	if (ask.kind === "review" || ask.kind === "ban") {
		const ban = parseBanInput(ask.values);
		if (!ban.ok) return fail(ban.problem);
		const checked = await checkBan(ctx, settings, loaded.dns, caller, ban.value.value, now);
		if (!checked.ok) {
			if (checked.problem.key === "dnsJustLoaded") out.extra += DNS_CALLS;
			return fail(checked.problem);
		}
		// Demo data: the review runs its checks, and nothing is ever sent.
		if (mode === "demo") return ask.kind === "review" ? { ...out, review: { check: checked.value, input: ban.value } } : demo(out, lang);
		if (!result.ok) return fail(result.problem);
		if (!source?.lapi) return fail({ key: "noNetwork" });
		if (ask.kind === "ban") {
			const res = await addBan(ctx, source.lapi, settings, loaded.dns, caller, ban.value, now);
			if (!res.ok) return fail(res.problem);
			const key = res.value.ownChecked ? "banDone" : "banDoneUnchecked";
			return done(out, lang, problemText(lang, { key, params: { type: res.value.type, value: res.value.value, duration: res.value.duration } }));
		}
		// The review runs every rule the ban will, the allowlist included.
		const allow = await checkAllowlist(source.lapi, checked.value.value);
		if (!allow.ok) return fail(allow.problem);
		// And says when the community blocklist already blocks the address.
		// Informational: a failed lookup leaves the note out.
		const look = await source.lapi.alerts({ scope: checked.value.scope, value: checked.value.value, activeOnly: true, limit: 20, simulated: true, blocklists: "include" });
		const blocklisted =
			look.ok &&
			look.value.some((alert) =>
				(alert.decisions ?? []).some((d) => isBlocklistDecision(d) && sameNetwork(d.value, checked.value.value) && (parseGoDuration(d.duration) ?? 0) > 0),
			);
		return { ...out, review: { check: checked.value, input: ban.value, ...(blocklisted && { blocklisted }) } };
	}
	if (mode === "demo") return demo(out, lang);
	if (!result.ok) return fail(result.problem);
	if (!source?.lapi) return fail({ key: "noNetwork" });
	let res: WriteResult<string>;
	if (ask.kind === "decision") {
		const r = await removeDecision(source.lapi, ask.id);
		res = r.ok ? { ok: true, value: problemText(lang, { key: "decisionRemoved", params: { id: r.value.id } }) } : r;
	} else if (ask.kind === "unban") {
		const r = await removeBansOn(source.lapi, ask.value, callsLeft());
		res = r.ok
			? {
					ok: true,
					value: problemText(lang, {
						key: r.value.remaining > 0 ? "removedSome" : "removedAll",
						params: { count: r.value.removed, remaining: r.value.remaining, value: r.value.value },
					}),
				}
			: r;
	} else {
		const r = await deleteAlert(ctx, source.lapi, ask.id, settings.timeZone, callsLeft());
		// The log's queries and write are not LAPI calls: count them at their most.
		if (r.ok) out.extra += LOG_QUERIES + 1;
		res = r.ok ? { ok: true, value: problemText(lang, { key: "alertDeleted", params: { id: r.value.id } }) } : r;
	}
	return res.ok ? done(out, lang, res.value) : fail(res.problem);
}

function done(out: WriteOutcome, _lang: Lang, message: string): WriteOutcome {
	return { ...out, wrote: true, toast: { message, type: "success" } };
}

function demo(out: WriteOutcome, lang: Lang): WriteOutcome {
	return { ...out, toast: { message: t(lang, "demoNothingChanged"), type: "success" } };
}
