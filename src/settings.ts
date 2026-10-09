/**
 * Reading the plugin's configuration.
 *
 * Everything comes out of `ctx.settings.list()` in one call rather than
 * one `get()` per key: a sandboxed invocation on Cloudflare gets ten
 * subrequests and every settings, KV and storage call spends one.
 *
 * `ctx.settings.get()` returns `null` for an unset key. Defaults declared
 * in `settingsSchema` are applied by the admin form when it saves, not
 * when the value is read, so every default is applied again here.
 */

import type { PluginContext } from "emdash/plugin";

import type { MessageKey, Problem } from "./i18n.js";
import { normalizeBaseUrl } from "./lapi/client.js";
import { overlaps, parseNetwork, parseNetworkList, RESERVED, type Network } from "./net/ip.js";
import { validZone } from "./sync/time.js";
import { resolveTimeZone } from "./time/zone.js";
import { clampNumber, str } from "./values.js";

export interface CrowdSecSettings {
	/** The LAPI URL without a trailing slash or `/v1`. */
	lapiUrl: string;
	machineId: string;
	password: string;
	syncInterval: string;
	retentionDays: number;
	includeSimulated: boolean;
	/** Writes are refused everywhere while this is off. */
	allowChanges: boolean;
	protectedAddresses: Network[];
	/** Entries of the protected addresses setting that are not addresses. */
	protectedInvalid: string[];
	/** The IANA time zone every day is counted in. */
	timeZone: string;
	/** The security engine's and the firewall bouncer's Prometheus endpoints. Empty is off, and so is a URL that cannot be used. */
	engineMetricsUrl: string;
	firewallMetricsUrl: string;
	/** Why a metrics URL that was entered cannot be used. */
	metricsProblems: { engine?: Problem; firewall?: Problem };
	/** Display names for CrowdSec agents, by `machine_id`. */
	engineNames: Record<string, string>;
}

export const DEFAULT_SYNC_INTERVAL = "*/15 * * * *";
export const DEFAULT_RETENTION_DAYS = 90;
export const MAX_RETENTION_DAYS = 400;

export type SettingsResult =
	| { ok: true; settings: CrowdSecSettings }
	| { ok: false; missing: string[]; problem: Problem; partial: CrowdSecSettings };

export async function readSettings(ctx: PluginContext): Promise<SettingsResult> {
	const raw = new Map<string, unknown>();
	for (const entry of await ctx.settings.list()) raw.set(entry.key, entry.value);
	return settingsFrom(raw);
}

export function settingsFrom(raw: Map<string, unknown>): SettingsResult {
	const { networks, invalid } = parseNetworkList(raw.get("protectedAddresses"));
	const enteredUrl = normalizeBaseUrl(str(raw.get("lapiUrl")));
	const urlKey = enteredUrl ? lapiUrlProblem(enteredUrl) : null;
	const settings: CrowdSecSettings = {
		// A URL that cannot be used is never handed on, so no request is ever made to it.
		lapiUrl: urlKey ? "" : enteredUrl,
		machineId: str(raw.get("machineId")),
		password: typeof raw.get("machinePassword") === "string" ? (raw.get("machinePassword") as string) : "",
		syncInterval: str(raw.get("syncInterval")) || DEFAULT_SYNC_INTERVAL,
		retentionDays: clampNumber(raw.get("retentionDays"), 7, MAX_RETENTION_DAYS, DEFAULT_RETENTION_DAYS),
		includeSimulated: raw.get("includeSimulated") === true,
		allowChanges: raw.get("allowChanges") === true,
		protectedAddresses: networks,
		protectedInvalid: invalid,
		timeZone: validZone(raw.get("timeZone")),
		engineMetricsUrl: "",
		firewallMetricsUrl: "",
		metricsProblems: {},
		engineNames: parseEngineNames(raw.get("engineNames")),
	};
	// The metrics URLs follow the LAPI URL's rules. One that cannot be used
	// turns its charts off and shows on the setup check: the alerts still sync.
	for (const [key, field, which] of [
		["engineMetricsUrl", "engineMetricsUrl", "engine"],
		["firewallMetricsUrl", "firewallMetricsUrl", "firewall"],
	] as const) {
		const entered = str(raw.get(key));
		if (!entered) continue;
		const problem = lapiUrlProblem(entered);
		if (problem) settings.metricsProblems[which] = { key: problem, ...(problem !== "m6i" && { params: { url: entered } }) };
		else settings[field] = entered;
	}
	// An unknown zone is not quietly replaced for the sync: counting days in
	// another zone would read as a change of dataset and clear the store.
	// The pages use the default meanwhile.
	const zoneText = typeof raw.get("timeZone") === "string" ? (raw.get("timeZone") as string).trim() : "";
	const zoneProblem: Problem | null =
		zoneText && resolveTimeZone(zoneText, "") === "" ? { key: "m6g", params: { zone: zoneText.slice(0, 64) } } : null;

	if (urlKey) {
		// A URL with a user name or password in it is never repeated back.
		const params = urlKey === "m6i" ? undefined : { url: enteredUrl };
		return { ok: false, missing: [], problem: { key: urlKey, ...(params && { params }) }, partial: settings };
	}
	const missing: string[] = [];
	if (!settings.lapiUrl) missing.push("lapiUrl");
	if (!settings.machineId) missing.push("machineId");
	if (!settings.password) missing.push("machinePassword");
	if (missing.length > 0) {
		return { ok: false, missing, problem: { key: "m6y", params: { missing: missing.join(",") } }, partial: settings };
	}
	if (zoneProblem) return { ok: false, missing: [], problem: zoneProblem, partial: settings };
	return { ok: true, settings };
}

/**
 * The Engine names setting: `machine_id = Display name` entries, one per
 * line or separated by commas. An entry without `=`, or with either side
 * empty, is left out. A name is cut to 40 characters.
 */
export function parseEngineNames(raw: unknown): Record<string, string> {
	const out: Record<string, string> = {};
	if (typeof raw !== "string") return out;
	for (const entry of raw.split(/[\n,]/)) {
		const cut = entry.indexOf("=");
		if (cut < 0) continue;
		const id = entry.slice(0, cut).trim().slice(0, 200);
		const name = entry.slice(cut + 1).trim().slice(0, 40);
		if (id && name && Object.keys(out).length < 100) out[id] = name;
	}
	return out;
}

/**
 * Why a LAPI URL cannot be used, or null. Only `https://` is accepted: the
 * password and the token cross the internet. A URL carrying a user name or
 * password is refused, and so is a private or internal address, which
 * EmDash would refuse to fetch anyway.
 */
export function lapiUrlProblem(raw: string): MessageKey | null {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return "m6d";
	}
	if (url.username || url.password) return "m6i";
	if (url.protocol !== "https:") return url.protocol === "http:" ? "m6f" : "m6d";
	if (url.search || url.hash) return "m6d";
	const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	const literal = parseNetwork(host);
	if (literal && RESERVED.some((reserved) => overlaps(literal, reserved))) return "m6e";
	if (!literal && (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || !host.includes("."))) {
		return "m6e";
	}
	return null;
}

/** The settings whatever their state, for readers that only need a value or two. */
export function settingsOf(result: SettingsResult): CrowdSecSettings {
	return result.ok ? result.settings : result.partial;
}

/**
 * Which stored data the settings describe. Rows read from one LAPI, with
 * simulated alerts or counted in another time zone must never be read as
 * these settings' rows, so a change here clears the store and starts again.
 */
export function datasetOf(settings: CrowdSecSettings): string {
	const base = `lapi|${settings.lapiUrl}`;
	return `${base}|${settings.includeSimulated}|${settings.timeZone}`;
}
