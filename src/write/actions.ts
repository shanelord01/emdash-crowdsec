/**
 * The changes the plugin can make in CrowdSec, and every check in front of
 * them. Shared by the admin pages and the MCP tools, so both refuse the
 * same things in the same words.
 *
 * Nothing here runs unless the Allow changes setting is on, the data
 * source is a LAPI, and the caller is an administrator. The admin pages
 * all post to one route, which editors may call to read, so the role is
 * checked here on the host-attested `routeCtx.user`. The MCP write tools
 * sit on their own routes with `plugins:manage`, which the host enforces
 * before the plugin runs.
 *
 * Adding a ban does what `cscli decisions add` does: one alert with one
 * decision, `origin: "cscli"`. LAPI skips its allowlist check for an alert
 * that carries decisions, so the plugin asks `allowlists/check` first.
 *
 * Deleting an alert deletes its decisions with it, and a decision deleted
 * that way never reaches a bouncer that had not polled yet: the ban stays
 * in the firewall until it expires. So an alert is deleted only once its
 * decisions ended more than two minutes ago. Bans are removed by deleting
 * the decision itself, which bouncers do hear about.
 */

import type { PluginContext } from "emdash/plugin";

import { failure, type Problem } from "../i18n.js";
import type { LapiClient } from "../lapi/client.js";
import { isBlocklistDecision } from "../lapi/blocklist.js";
import type { RawDecision } from "../lapi/types.js";
import { checkBanTarget, displayNetwork, isSingleAddress, parseNetwork, sameNetwork } from "../net/ip.js";
import { callerAddresses, DNS_KEY, dnsFresh, isLocalName, namesToResolve, protections, resolveNames, type DnsCache } from "../net/protect.js";
import type { CrowdSecSettings } from "../settings.js";
import { alertsStore } from "../store/access.js";
import { parseGoDuration, rfc3339 } from "../sync/time.js";

export const ADMIN_ROLE = 50;

/** The durations a ban may have, as offered and as LAPI is sent them (Go durations have no days). */
export const BAN_DURATIONS = { "1h": "1h", "4h": "4h", "24h": "24h", "7d": "168h", "30d": "720h" } as const;
export type BanDuration = keyof typeof BAN_DURATIONS;
export const BAN_TYPES = ["ban", "captcha"] as const;
export type BanType = (typeof BAN_TYPES)[number];

export const MAX_NOTE = 120;
/** How long after its decisions end an alert may be deleted. */
export const DELETE_GRACE_S = 120;

export interface Caller {
	user?: { id?: string; name?: string | null; role?: number } | null;
	requestMeta?: unknown;
	request?: { headers?: Record<string, string> };
	/** "mcp" when an MCP client calls: its own address is its egress, which may not be the person's. */
	channel?: "admin" | "mcp";
}

export type WriteResult<T> = { ok: true; value: T } | { ok: false; problem: Problem };

function refuse(key: Parameters<typeof failure>[0], params?: Record<string, string | number>): { ok: false; problem: Problem } {
	return { ok: false, problem: failure(key, params).problem };
}

/**
 * May this caller change anything? `requireRole` is false on the MCP
 * routes, whose `plugins:manage` permission the host has already enforced
 * (a token with no bound user has no role to read).
 */
export function writeGate(settings: CrowdSecSettings, caller: Caller, requireRole = true): WriteResult<null> {
	if (!settings.allowChanges) return refuse("changesOff");
	if (settings.source !== "lapi") return refuse("demoNoChanges");
	if (requireRole && (caller.user?.role ?? 0) < ADMIN_ROLE) return refuse("adminOnly");
	// An entry the plugin cannot read protects nothing, and the operator
	// believes it does: no change at all until it is fixed.
	if (settings.protectedInvalid.length > 0) return refuse("protectedInvalidRefuse", { entries: settings.protectedInvalid.join(", ") });
	return { ok: true, value: null };
}

/** Is a write control worth showing? The same test as `writeGate`, without the reason. */
export function canWrite(settings: CrowdSecSettings, caller: Caller): boolean {
	return writeGate(settings, caller).ok;
}

export interface BanInput {
	value: string;
	duration: BanDuration;
	type: BanType;
	note: string;
}

/** The ban form's or the tool's input, checked by hand: the routes are reachable without the MCP server's validation. */
export function parseBanInput(input: Record<string, unknown>): WriteResult<BanInput> {
	const value = typeof input.value === "string" ? input.value.trim() : "";
	if (!value) return refuse("invalidAddress");
	const duration = typeof input.duration === "string" && input.duration in BAN_DURATIONS ? (input.duration as BanDuration) : null;
	if (!duration) return refuse("invalidDuration");
	const type = input.type === undefined || input.type === "" ? "ban" : input.type;
	if (type !== "ban" && type !== "captcha") return refuse("invalidType");
	const note = typeof input.note === "string" ? input.note.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, MAX_NOTE) : "";
	return { ok: true, value: { value, duration, type, note } };
}

export interface BanCheck {
	value: string;
	scope: "Ip" | "Range";
	/** False when no address for the caller could be found, so the own-address rule could not run. */
	ownChecked: boolean;
}

/**
 * Every rule a ban has to pass before LAPI is asked anything: the built-in
 * refusals, the caller's own addresses, the site's and LAPI's addresses
 * and the Protected addresses setting.
 *
 * The site's and LAPI's addresses come from the DNS cache. A cold cache
 * is filled here and the ban refused with "try again", because doing both
 * in one invocation could run out of bridge calls halfway through.
 * Calls: none with a warm cache. With a cold one, two requests per
 * hostname and the cache write.
 */
export async function checkBan(
	ctx: PluginContext,
	settings: CrowdSecSettings,
	dns: DnsCache | null,
	caller: Caller,
	value: string,
	now: Date,
): Promise<WriteResult<BanCheck>> {
	const names = namesToResolve(ctx.site.url, settings.lapiUrl);
	// A local site name cannot be looked up, so a ban could cover the site
	// without anyone knowing. Bans stay refused until the site URL is public.
	const local = names.find(isLocalName);
	if (local) return refuse("localSiteName", { name: local });
	if (names.length > 0 && !dnsFresh(dns, names, now)) {
		if (!ctx.http) return refuse("noNetwork");
		const http = ctx.http;
		const looked = await resolveNames((url, init) => http.fetch(url, init), names, now);
		if (!looked.ok) return { ok: false, problem: looked.problem };
		await ctx.kv.set(DNS_KEY, looked.value);
		return refuse("dnsJustLoaded");
	}

	const callers = callerAddresses(caller);
	const check = checkBanTarget(
		value,
		protections({ callers, siteUrl: ctx.site.url, lapiUrl: settings.lapiUrl, dns, setting: settings.protectedAddresses }),
	);
	if (!check.ok) {
		if (check.reason === "rangeTooWide") return refuse("rangeTooWide", { widest: check.widest });
		if (check.reason === "hostBits") return refuse("hostBits", { meant: check.meant });
		if (check.reason === "protectedAddress") {
			const own = caller.channel === "mcp" ? "mcpClientAddress" : "ownAddress";
			const key = ({ caller: own, site: "siteAddress", lapi: "lapiAddress", setting: "settingAddress" } as const)[check.rule];
			return refuse(key, { match: check.match });
		}
		return refuse(check.reason);
	}
	return { ok: true, value: { value: check.value, scope: check.scope, ownChecked: callers.length > 0 } };
}

/** The reason recorded with a ban, as cscli writes it, with the note after it. */
export function banReason(type: BanType, caller: Caller, note: string): string {
	const who = caller.user?.name?.trim() || caller.user?.id || "an administrator";
	const reason = `manual '${type}' from 'emdash-crowdsec' by ${who}`;
	return note ? `${reason}: ${note}` : reason;
}

/** The alert `POST /v1/alerts` takes for one manual decision, the shape cscli sends. */
export function banAlert(check: BanCheck, input: BanInput, reason: string, now: Date): Record<string, unknown> {
	const at = rfc3339(now);
	return {
		scenario: reason,
		scenario_hash: "",
		scenario_version: "",
		message: reason,
		events_count: 1,
		events: [],
		capacity: 0,
		leakspeed: "0",
		simulated: false,
		start_at: at,
		stop_at: at,
		created_at: at,
		remediation: true,
		kind: "manual",
		source: { scope: check.scope, value: check.value, ip: check.value },
		decisions: [
			{
				duration: BAN_DURATIONS[input.duration],
				scope: check.scope,
				value: check.value,
				type: input.type,
				scenario: reason,
				origin: "cscli",
			},
		],
	};
}

/**
 * Add a ban or captcha. Calls: the checks above, then the login, the
 * allowlist check and the POST.
 */
export async function addBan(
	ctx: PluginContext,
	lapi: LapiClient,
	settings: CrowdSecSettings,
	dns: DnsCache | null,
	caller: Caller,
	input: BanInput,
	now: Date,
): Promise<WriteResult<{ value: string; type: BanType; duration: BanDuration; alertId: string; ownChecked: boolean }>> {
	const checked = await checkBan(ctx, settings, dns, caller, input.value, now);
	if (!checked.ok) return checked;

	const allow = await checkAllowlist(lapi, checked.value.value);
	if (!allow.ok) return allow;

	const reason = banReason(input.type, caller, input.note);
	const added = await lapi.addAlert(banAlert(checked.value, input, reason, now));
	if (!added.ok) return { ok: false, problem: added.problem };
	return {
		ok: true,
		value: {
			value: checked.value.value,
			type: input.type,
			duration: input.duration,
			alertId: added.value,
			ownChecked: checked.value.ownChecked,
		},
	};
}

/**
 * Refuse an address CrowdSec allowlists. LAPI skips its own check for an
 * alert that carries decisions, so the plugin asks first, and an answer it
 * cannot read refuses too. Calls: the login when it is the first, and the check.
 */
export async function checkAllowlist(lapi: LapiClient, value: string): Promise<WriteResult<null>> {
	const allow = await lapi.allowlisted(value);
	if (!allow.ok) return { ok: false, problem: allow.problem };
	if (allow.value.allowlisted) return refuse(allow.value.reason ? "allowlistedReason" : "allowlisted", { reason: allow.value.reason ?? "" });
	return { ok: true, value: null };
}

/** Remove one decision by id. Calls: the login and the DELETE. */
export async function removeDecision(lapi: LapiClient, id: unknown): Promise<WriteResult<{ id: number; removed: number }>> {
	const n = positiveId(id);
	if (n === null) return refuse("invalidId");
	const res = await lapi.deleteDecision(n);
	if (!res.ok) return { ok: false, problem: res.problem };
	if (res.value === 0) return refuse("decisionGone");
	return { ok: true, value: { id: n, removed: res.value } };
}

/** The most bridge calls one LAPI request can take: the request, and the invocation's login when it is the first. */
export const REQUEST_WORST = 2;

/**
 * Remove the active decisions on exactly this address or range.
 *
 * Found with `scope` and `value`, never `ip=`, which also matches alerts
 * with an empty source. Only decisions whose value is the same address or
 * range are deleted, by id. Deletes stop while another could no longer fit
 * in `callsAvailable` at its worst. The answer says how many are left for
 * another try.
 */
export async function removeBansOn(
	lapi: LapiClient,
	raw: unknown,
	callsAvailable: number,
): Promise<WriteResult<{ value: string; removed: number; remaining: number; ids: number[] }>> {
	const parsed = parseNetwork(raw);
	if (!parsed) return refuse("invalidAddress");
	// LAPI stores an IPv4 address in IPv4 form, so `::ffff:a.b.c.d` is searched as `a.b.c.d`.
	const value = displayNetwork(parsed);
	const network = parseNetwork(value)!;
	const start = lapi.calls;
	// One address's search includes the community blocklist, so it can say
	// when that is all that blocks it.
	const res = await lapi.alerts({ scope: isSingleAddress(network) ? "Ip" : "Range", value, activeOnly: true, limit: 50, simulated: true, blocklists: "include" });
	if (!res.ok) return { ok: false, problem: res.problem };

	const ids = new Set<number>();
	let blocklisted = false;
	for (const alert of res.value) {
		for (const decision of alert.decisions ?? []) {
			if (!activeDecision(decision) || typeof decision.id !== "number" || !sameNetwork(decision.value, value)) continue;
			// Blocklist decisions are not removed: CrowdSec adds them back on its next pull.
			if (isBlocklistDecision(decision)) blocklisted = true;
			else ids.add(decision.id);
		}
	}
	if (ids.size === 0) return refuse(blocklisted ? "onlyBlocklisted" : "noActiveBan", { value });

	const removed: number[] = [];
	for (const id of ids) {
		if (lapi.calls - start + REQUEST_WORST > callsAvailable) break;
		const del = await lapi.deleteDecision(id);
		if (!del.ok) return { ok: false, problem: del.problem };
		if (del.value > 0) removed.push(id);
	}
	const tried = removed.length;
	return { ok: true, value: { value, removed: tried, remaining: ids.size - tried, ids: removed } };
}

function activeDecision(decision: RawDecision): boolean {
	const left = parseGoDuration(decision.duration);
	return left !== null && left > 0;
}

/**
 * Delete one alert by id, never in bulk, and only once its decisions ended
 * more than `DELETE_GRACE_S` ago. Calls: the login, the GET, the DELETE
 * and the stored row's delete, all inside `callsAvailable`. When too few
 * are left after the GET, it asks to be tried again rather than stop
 * between the two deletes.
 */
export async function deleteAlert(ctx: PluginContext, lapi: LapiClient, id: unknown, callsAvailable = 8): Promise<WriteResult<{ id: number }>> {
	const n = positiveId(id);
	if (n === null) return refuse("invalidId");
	const start = lapi.calls;
	const found = await lapi.alert(n);
	if (!found.ok) return { ok: false, problem: found.problem };
	if (!found.value) {
		// LAPI no longer has it, so the stored row goes too.
		await alertsStore(ctx)?.deleteMany([String(n)]);
		return refuse("alertGone", { id: n });
	}

	for (const decision of found.value.decisions ?? []) {
		const left = parseGoDuration(decision.duration);
		// Fail closed: a decision whose end cannot be read may still be in force.
		if (left === null) return refuse("alertDecisionUnknown", { id: n });
		if (left > 0) return refuse("alertHasActiveDecision", { id: n });
		if (left > -DELETE_GRACE_S) return refuse("alertDecisionJustEnded", { id: n });
	}

	// The DELETE at its worst and the stored row's delete must both fit.
	if (lapi.calls - start + REQUEST_WORST + 1 > callsAvailable) return refuse("tryAgain");
	const res = await lapi.deleteAlert(n);
	if (!res.ok) return { ok: false, problem: res.problem };
	await alertsStore(ctx)?.deleteMany([String(n)]);
	return { ok: true, value: { id: n } };
}

function positiveId(value: unknown): number | null {
	const n = typeof value === "string" && /^\d{1,15}$/.test(value) ? Number(value) : value;
	return typeof n === "number" && Number.isSafeInteger(n) && n > 0 ? n : null;
}
