import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { expect, vi } from "vitest";

import { alertSearch } from "../src/lapi/client.js";
import type { AlertQuery, RawAlert } from "../src/lapi/types.js";
import type { SyncState } from "../src/sync/scheduler.js";
import { USER_AGENT } from "../src/version.js";
import sample from "./fixtures/alerts-sample.json?raw";
import { seedStore } from "./seed.js";

/**
 * Fixtures for tests that run the plugin inside the runtime test host.
 * Each test file creates and disposes its own host.
 */

export const LAPI = "https://lapi.example.test/crowdsec-lapi";
export const SITE = "https://www.example.test";
export const ZONE = "Australia/Sydney";

/** Eight real alerts, anonymised: addresses in 203.0.113.0/24, host www.example.com. */
export function sampleAlerts(): RawAlert[] {
	return JSON.parse(sample) as RawAlert[];
}

export async function newHost(_source: "lapi" = "lapi", extra: Record<string, unknown> = {}) {
	vi.stubEnv("EMDASH_ENCRYPTION_KEY", "emdash_enc_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	const runtime = await createPluginRuntimeTestHost({ site: { url: SITE, locale: "en", trailingSlash: "never" } });
	const saved = await runtime.actions.plugin.updateSettings({ ...hostSettings, ...extra });
	expect(saved).toMatchObject({ success: true });
	return runtime;
}

/** The settings `newHost` saves, before its extras. */
export const hostSettings = { lapiUrl: LAPI, machineId: "emdash-crowdsec", machinePassword: "secret-password", timeZone: ZONE };

/**
 * A host whose store already holds `days` of generated alerts, as if the
 * sync had read them (`tests/seed.ts`). Pages and tools that read storage
 * work against it without a LAPI.
 */
export async function seededHost(extra: Record<string, unknown> = {}, days = 7) {
	const runtime = await newHost("lapi", extra);
	const now = new Date();
	await seedStore(runtime, { ...hostSettings, ...extra }, now.getTime() - days * 86_400_000, now);
	return runtime;
}

export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Answer `count` logins: each invocation that needs LAPI logs in once and keeps no token. */
export async function respondLogin(runtime: PluginRuntimeTestHost, status = 200, count = 1) {
	for (let i = 0; i < count; i++) {
		await runtime.http.respond(
			`${LAPI}/v1/watchers/login`,
			status === 200
				? json({ code: 200, expire: new Date(Date.now() + 3_600_000).toISOString(), token: "fresh-token" })
				: json({ code: status, message: "incorrect Username or Password" }, status),
		);
	}
}

/**
 * Answer an alert search whose `since` and `until` the plugin works out
 * from its own clock. The host matches URLs to the character, so every URL
 * the run could build over the next few seconds gets the same answer.
 */
export async function respondSearch(runtime: PluginRuntimeTestHost, query: (now: Date) => AlertQuery, body: unknown, opts: { seconds?: number; status?: number } = {}) {
	const start = Date.now();
	const urls = new Set<string>();
	for (let ms = 0; ms <= (opts.seconds ?? 8) * 1000; ms += 100) {
		const now = new Date(start + ms);
		// LAPI's Date header has whole seconds, so the measured skew can move
		// a duration by a second either way.
		for (const skew of [-1000, 0, 1000]) urls.add(`${LAPI}/v1/alerts?${alertSearch(query(now), new Date(now.getTime() + skew))}`);
	}
	for (const url of urls) await runtime.http.respond(url, json(body, opts.status ?? 200));
	return urls;
}

/** A stored state. One from 0.1.1 on has moved its alert rows into the log, unless the test says otherwise. */
export async function setState(runtime: PluginRuntimeTestHost, state: SyncState) {
	await runtime.fixtures.plugin.kv("sync.state", { logMigrated: true, ...state });
}

export const tick = (runtime: PluginRuntimeTestHost, name = "sync") => () =>
	runtime.transport.invokeHook("cron", { name, scheduledAt: new Date().toISOString() });

export const ADMIN = { id: "admin-1", email: "admin@example.test", name: "Ada Admin", role: 50, createdAt: "2026-01-01T00:00:00.000Z" };
export const EDITOR = { id: "editor-1", email: "editor@example.test", name: "Ed Editor", role: 40, createdAt: "2026-01-01T00:00:00.000Z" };

/** A DNS cache that already knows the site's and the LAPI's addresses. */
export async function warmDns(runtime: PluginRuntimeTestHost, site = ["198.51.100.10"], lapi = ["198.51.100.20"]) {
	await runtime.fixtures.plugin.kv("sync.dns", {
		at: new Date().toISOString(),
		key: ["lapi.example.test", "www.example.test"].join(","),
		addresses: { "www.example.test": site, "lapi.example.test": lapi },
	});
}

export function expectUserAgent(runtime: PluginRuntimeTestHost) {
	const lapiRequests = runtime.http.requests().filter((r) => r.url.startsWith(LAPI));
	expect(lapiRequests.length).toBeGreaterThan(0);
	for (const request of lapiRequests) expect(request.headers["user-agent"]).toBe(USER_AGENT);
}
