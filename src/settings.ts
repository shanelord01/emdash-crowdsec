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

export type SourceId = "lapi" | "demo";

export interface CrowdSecSettings {
	source: SourceId;
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
		source: raw.get("source") === "demo" ? "demo" : "lapi",
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
	};
	// An unknown zone is not quietly replaced for the sync: counting days in
	// another zone would read as a change of dataset and clear the store.
	// The pages use the default meanwhile.
	const zoneText = typeof raw.get("timeZone") === "string" ? (raw.get("timeZone") as string).trim() : "";
	const zoneProblem: Problem | null =
		zoneText && resolveTimeZone(zoneText, "") === "" ? { key: "timeZoneInvalid", params: { zone: zoneText.slice(0, 64) } } : null;
	if (settings.source === "demo") return zoneProblem ? { ok: false, missing: [], problem: zoneProblem, partial: settings } : { ok: true, settings };

	if (urlKey) {
		// A URL with a user name or password in it is never repeated back.
		const params = urlKey === "urlUserinfo" ? undefined : { url: enteredUrl };
		return { ok: false, missing: [], problem: { key: urlKey, ...(params && { params }) }, partial: settings };
	}
	const missing: string[] = [];
	if (!settings.lapiUrl) missing.push("lapiUrl");
	if (!settings.machineId) missing.push("machineId");
	if (!settings.password) missing.push("machinePassword");
	if (missing.length > 0) {
		return { ok: false, missing, problem: { key: "notConfigured", params: { missing: missing.join(",") } }, partial: settings };
	}
	if (zoneProblem) return { ok: false, missing: [], problem: zoneProblem, partial: settings };
	return { ok: true, settings };
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
		return "urlInvalid";
	}
	if (url.username || url.password) return "urlUserinfo";
	if (url.protocol !== "https:") return url.protocol === "http:" ? "urlNotHttps" : "urlInvalid";
	if (url.search || url.hash) return "urlInvalid";
	const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	const literal = parseNetwork(host);
	if (literal && RESERVED.some((reserved) => overlaps(literal, reserved))) return "urlPrivate";
	if (!literal && (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || !host.includes("."))) {
		return "urlPrivate";
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
	const base = settings.source === "demo" ? "demo" : `lapi|${settings.lapiUrl}`;
	return `${base}|${settings.includeSimulated}|${settings.timeZone}`;
}
