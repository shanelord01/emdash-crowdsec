import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RawAlert } from "../src/lapi/types.js";
import { DEFAULT_BATCH, floorOf, type SyncState } from "../src/sync/scheduler.js";
import { TOOL_ROUTES } from "../src/tools/load.js";
import {
	ALERTS_DELETE,
	ALERTS_PATH,
	ALERTS_VIEW,
	BAN_CONFIRM,
	BAN_REVIEW,
	DECISIONS_PATH,
	DECISIONS_REMOVE,
	PAGE_REFRESH,
	RANGE_ACTION,
	SECURITY_PATH,
	SETUP_ACTION,
	WIDGET_REFRESH,
} from "../src/ui/ids.js";
import { bridgeCalls } from "./bridge-calls.js";
import { failure } from "../src/i18n.js";
import { settingsFrom } from "../src/settings.js";
import { readActive } from "../src/ui/decisions.js";
import { ADMIN, json, LAPI, newHost, respondLogin, respondSearch, sampleAlerts, setState, tick, warmDns, ZONE } from "./host.js";

/**
 * Every invocation, at its worst case, against EmDash's sandbox limit.
 *
 * A sandboxed invocation may make ten subrequests and each `ctx` call is
 * one. The eleventh throws "Too many subrequests" on Cloudflare and aborts
 * the tick or the render. The test host does not enforce the limit, so each
 * test counts the calls and also checks the invocation did its full share
 * of work, so a fixture too small to reach the worst case fails instead of
 * passing quietly.
 */

const LIMIT = 10;
const DATASET = `lapi|${LAPI}|false|${ZONE}`;

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

/** `count` alerts, newest first, one every `stepMs` back from `newest`, spread over many local days. */
function alertsBack(count: number, newest: number, stepMs: number): RawAlert[] {
	const base = sampleAlerts();
	return Array.from({ length: count }, (_, i) => {
		const at = new Date(newest - i * stepMs).toISOString();
		return { ...base[i % base.length]!, id: 50_000 + i, start_at: at, created_at: at };
	});
}

async function state(runtime: PluginRuntimeTestHost) {
	return (await runtime.inspect.kv.get<SyncState>("sync.state")) ?? {};
}

function within(calls: string[]) {
	expect(calls.length, calls.join(", ")).toBeLessThanOrEqual(LIMIT);
}

const DAY = 86_400_000;

describe("sync ticks against a LAPI", () => {
	it("a first tick: lease, settings, login, a full batch over 30 days, both writes, the state and the chained run", async () => {
		host = await newHost("lapi");
		await respondLogin(host);
		const batch = alertsBack(DEFAULT_BATCH, Date.now() - 60_000, (29 * DAY) / DEFAULT_BATCH);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 30 * DAY), limit: DEFAULT_BATCH, simulated: false }), batch);

		const calls = await bridgeCalls(tick(host));

		within(calls);
		expect(calls).toEqual(expect.arrayContaining(["kvGetVersioned", "kvCompareAndSet", "storageGetMany", "storagePutMany", "cronSchedule"]));
		expect(calls.filter((c) => c === "storagePutMany")).toHaveLength(2);
		expect((await host.inspect.storage.list("days")).length).toBeGreaterThan(25);
	});

	it("a chained catch-up run of the same size", async () => {
		host = await newHost("lapi");
		const now = Date.now();
		const to = new Date(now - 10 * DAY).toISOString();
		await setState(host, { blocklistPurged: true, dataset: DATASET, head: new Date(now).toISOString(), gaps: [{ from: floorOf({ retentionDays: 90, timeZone: ZONE }, new Date(now)), to }], lastSync: to });
		await respondLogin(host);
		const batch = alertsBack(DEFAULT_BATCH, Date.parse(to) - 60_000, (29 * DAY) / DEFAULT_BATCH);
		await respondSearch(host, () => ({ since: new Date(Date.parse(to) - 30 * DAY), until: new Date(to), limit: DEFAULT_BATCH, simulated: false }), batch);

		const calls = await bridgeCalls(tick(host, "catchup-a"));

		within(calls);
		expect(calls).toContain("cronSchedule");
		expect((await state(host)).chain?.next).toBe("catchup-b");
	});

	it("a forward tick whose full batch leaves a gap", async () => {
		host = await newHost("lapi");
		const head = new Date(Date.now() - 6 * 3_600_000).toISOString();
		await setState(host, { blocklistPurged: true, dataset: DATASET, head, gaps: [], slot: 0, lastSync: head });
		await respondLogin(host);
		const batch = alertsBack(DEFAULT_BATCH, Date.now() - 60_000, 60_000);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - DAY), limit: DEFAULT_BATCH, simulated: false }), batch);

		const calls = await bridgeCalls(tick(host));

		within(calls);
		expect((await state(host)).gaps).toHaveLength(1);
	});

	it("the bans slot when the DNS cache for the ban protections is cold: two hostnames, A and AAAA each", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await setState(host, { blocklistPurged: true, dataset: DATASET, head: new Date().toISOString(), gaps: [], slot: 2, lastSync: "x" });
		for (const name of ["www.example.test", "lapi.example.test"]) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 1, data: "198.51.100.10" }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({ Answer: [{ type: 28, data: "2001:db8::10" }] }));
		}

		const calls = await bridgeCalls(tick(host));

		within(calls);
		expect(calls.filter((c) => c === "httpFetch")).toHaveLength(4);
		await expect(host.inspect.kv.get("sync.dns")).resolves.not.toBeNull();
	});

	it("the bans slot when the lookup fails after three requests, which still counts the bans", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await setState(host, { blocklistPurged: true, dataset: DATASET, head: new Date().toISOString(), gaps: [], slot: 2, lastSync: "x" });
		// Names go in order: the LAPI host answers both, the site's first request fails.
		await host.http.respond("https://cloudflare-dns.com/dns-query?name=lapi.example.test&type=A", json({ Answer: [{ type: 1, data: "198.51.100.20" }] }));
		await host.http.respond("https://cloudflare-dns.com/dns-query?name=lapi.example.test&type=AAAA", json({}));
		await host.http.respond("https://cloudflare-dns.com/dns-query?name=www.example.test&type=A", json({}, 500));
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json(sampleAlerts()));

		const calls = await bridgeCalls(tick(host));

		within(calls);
		expect(calls.filter((c) => c === "httpFetch")).toHaveLength(5);
		expect((await state(host)).active?.bans).toBeGreaterThan(0);
		expect((await state(host)).dnsRetryAt).toEqual(expect.any(String));
	});

	it("a Refresh that finds the lease taken, and schedules itself again", async () => {
		host = await newHost("lapi");
		await setState(host, { lease: { owner: "other", until: new Date(Date.now() + 60_000).toISOString() } });
		const calls = await bridgeCalls(tick(host, "refresh"));
		within(calls);
		expect(calls).toEqual(["kvGetVersioned", "cronSchedule"]);
	});

	it("the bans slot with a warm cache, and the bans and refresh one-shots", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await warmDns(host);
		const activeUrl = `${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`;
		for (const [name, slot] of [["sync", 2], ["bans", 0]] as const) {
			await setState(host, { blocklistPurged: true, dataset: DATASET, head: new Date().toISOString(), gaps: [], slot, lastSync: "x" });
			await respondLogin(host);
			await host.http.respond(activeUrl, json(sampleAlerts()));
			within(await bridgeCalls(tick(host, name)));
			expect((await state(host)).active?.bans).toBeGreaterThan(0);
		}
		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - DAY), limit: DEFAULT_BATCH, simulated: false }), sampleAlerts());
		within(await bridgeCalls(tick(host, "refresh")));
	});

	it("every tick of a wipe after the dataset changed, until it completes", async () => {
		host = await newHost("lapi");
		for (let i = 0; i < 250; i++) await host.fixtures.plugin.storage("alerts", String(i), { id: i, startedAt: "2026-10-01T00:00:00.000Z" });
		for (let i = 0; i < 120; i++) await host.fixtures.plugin.storage("days", `d${i}`, { date: `d${i}` });
		await setState(host, { dataset: "lapi|https://old.example.test|false|Australia/Sydney" });

		let ticks = 0;
		for (; ticks < 10 && (await state(host)).dataset; ticks++) within(await bridgeCalls(tick(host)));
		expect(ticks).toBeGreaterThan(1);
		await expect(host.inspect.storage.list("alerts")).resolves.toEqual([]);
		await expect(host.inspect.storage.list("days")).resolves.toEqual([]);
	});

	it("a nightly prune with more to delete than one run can", async () => {
		host = await newHost("lapi");
		for (let i = 0; i < 450; i++) await host.fixtures.plugin.storage("alerts", String(i), { id: i, startedAt: "2025-01-01T00:00:00.000Z" });
		within(await bridgeCalls(tick(host, "reconcile")));
		const left = (await host.inspect.storage.list("alerts")).length;
		expect(left).toBeGreaterThan(0);
		expect(left).toBeLessThan(450);
	});

	it("a tick that finds the lease taken", async () => {
		host = await newHost("lapi");
		await setState(host, { lease: { owner: "other", until: new Date(Date.now() + 60_000).toISOString() } });
		within(await bridgeCalls(tick(host)));
	});
});

describe("the live read of active decisions", () => {
	it("asks three times at most, half as many each time after an answer over 8 MiB", async () => {
		// The test host cannot stage an answer over 8 MiB, so the read runs on
		// a source that refuses twice. With kv.list, settings.list and the
		// login, the Decisions page and active_decisions spend six calls on it.
		const sizes: number[] = [];
		const source = {
			id: "lapi" as const,
			lapi: null,
			calls: () => sizes.length,
			skew: () => undefined,
			alerts: async (query: { limit: number }) => {
				sizes.push(query.limit);
				return sizes.length < 3 ? failure("tooLarge") : { ok: true as const, value: sampleAlerts() };
			},
		};
		const settings = settingsFrom(new Map<string, unknown>([["source", "demo"]]));
		const res = await readActive(source, (settings.ok ? settings.settings : settings.partial), 100);
		expect(sizes).toEqual([100, 50, 25]);
		expect(res.ok).toBe(true);
		expect(2 + 1 + sizes.length).toBeLessThanOrEqual(LIMIT);

		sizes.length = 0;
		source.alerts = async (query: { limit: number }) => (sizes.push(query.limit), failure("tooLarge"));
		const failed = await readActive(source, (settings.ok ? settings.settings : settings.partial), 100);
		expect(sizes).toHaveLength(3);
		expect(failed.ok ? null : failed.problem.key).toBe("tooLarge");
	});
});

describe("admin requests", () => {
	const activeUrl = `${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`;

	async function withDays(runtime: PluginRuntimeTestHost) {
		for (let i = 0; i < 180; i++) {
			const date = new Date(Date.now() - i * DAY).toISOString().slice(0, 10);
			await runtime.fixtures.plugin.storage("days", date, { date, alerts: 3, waf: 1, bot: 1, behaviour: 1, manual: 0, decisions: 1, bans: 1, scenarios: { a: 3 }, countries: { NL: 3 }, asNames: {}, paths: {}, ips: {}, seen: [], updatedAt: "" });
		}
	}

	it("the widget, before the first sync, and its Refresh", async () => {
		host = await newHost("demo");
		const load = await bridgeCalls(() => host!.admin.loadWidget("security"));
		within(load);
		// The sync, the nightly prune, the daily blocklist count and, with demo data, the metrics sampler.
		expect(load.filter((c) => c === "cronSchedule")).toHaveLength(4);
		within(await bridgeCalls(() => host!.admin.act("widget:security", WIDGET_REFRESH)));
	});

	it("the Security page over 90 days, its Refresh and the setup check with a cold DNS cache", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await withDays(host);
		const page = await bridgeCalls(() => host!.admin.act(SECURITY_PATH, RANGE_ACTION, { value: 90 }));
		within(page);
		expect(page.filter((c) => c === "storageQuery")).toHaveLength(2);
		within(await bridgeCalls(() => host!.admin.act(SECURITY_PATH, PAGE_REFRESH, { value: 90 })));

		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 3_600_000), limit: 1, simulated: false }), []);
		for (const name of ["www.example.test", "lapi.example.test"]) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 1, data: "198.51.100.10" }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({}));
		}
		const setup = await bridgeCalls(() => host!.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 }));
		within(setup);
		expect(setup.filter((c) => c === "httpFetch")).toHaveLength(6);
	});

	it("the Alerts page, filtered, and a delete that reads the page again", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await withDays(host);
		within(await bridgeCalls(() => host!.admin.act(ALERTS_PATH, `${ALERTS_VIEW}|waf|`)));
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions: [{ id: 5, duration: "-10m" }] }));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ nbDeleted: "1" }));
		const calls = await bridgeCalls(() => host!.admin.act(ALERTS_PATH, `${ALERTS_DELETE}||`, { value: 625 }));
		within(calls);
		expect(calls.filter((c) => c === "httpFetch")).toHaveLength(3);
		expect(calls).toContain("storageDeleteMany");
	});

	it("the Decisions page, a Remove, a review with a cold DNS cache, and a confirmed ban", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await respondLogin(host, 200, 6);
		for (let i = 0; i < 4; i++) await host.http.respond(activeUrl, json(sampleAlerts()));
		within(await bridgeCalls(() => host!.admin.loadPage(DECISIONS_PATH)));

		await host.http.respond(`${LAPI}/v1/decisions/1185224`, json({ nbDeleted: "1" }));
		const remove = await bridgeCalls(() => host!.admin.act(DECISIONS_PATH, `${DECISIONS_REMOVE}|asc`, { value: 1185224 }));
		within(remove);
		expect(remove).toContain("cronSchedule");

		for (const name of ["www.example.test", "lapi.example.test"]) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 1, data: "198.51.100.10" }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({}));
		}
		const values = { value: "203.0.113.70", duration: "4h", type: "ban", note: "" };
		within(await bridgeCalls(() => host!.admin.submit(DECISIONS_PATH, BAN_REVIEW, values)));
		// A review with a warm cache: the login, the allowlist check, the blocklist lookup and the list read again.
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.70&has_active_decision=true&simulated=true&limit=20`, json([]));
		const review = await bridgeCalls(() => host!.admin.submit(DECISIONS_PATH, BAN_REVIEW, values));
		within(review);
		expect(review.filter((c) => c === "httpFetch")).toHaveLength(4);

		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["903"], 201));
		const ban = await bridgeCalls(() => host!.admin.act(DECISIONS_PATH, BAN_CONFIRM, { value: values }));
		within(ban);
		expect(ban).toContain("cronSchedule");
	});
});

describe("MCP tools", () => {
	async function call(runtime: PluginRuntimeTestHost, route: string, body: unknown) {
		return await bridgeCalls(async () => {
			const response = await runtime.actions.routes.request(route, { body, user: ADMIN, headers: { "X-EmDash-Request": "1", "X-Real-IP": "198.51.100.7" } });
			expect(response.status).toBe(200);
		});
	}

	it("the read tools", async () => {
		host = await newHost("lapi");
		for (let i = 0; i < 180; i++) {
			const date = new Date(Date.now() - i * DAY).toISOString().slice(0, 10);
			await host.fixtures.plugin.storage("days", date, { date, alerts: 1, waf: 1, bot: 0, behaviour: 0, manual: 0, decisions: 0, bans: 0, scenarios: {}, countries: {}, asNames: {}, paths: {}, ips: {}, seen: [], updatedAt: "" });
		}
		within(await call(host, TOOL_ROUTES.summary, { days: 90 }));
		within(await call(host, TOOL_ROUTES.top, { days: 90, limit: 25 }));
		await respondLogin(host, 200, 2);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json(sampleAlerts()));
		within(await call(host, TOOL_ROUTES.decisions, { limit: 100 }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&simulated=false&limit=50`, json(sampleAlerts()));
		within(await call(host, TOOL_ROUTES.ipAlerts, { address: "203.0.113.14" }));
	});

	it("ban_ip with a cold DNS cache, then a ban", async () => {
		host = await newHost("lapi", { allowChanges: true });
		for (const name of ["www.example.test", "lapi.example.test"]) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 1, data: "198.51.100.10" }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({}));
		}
		within(await call(host, TOOL_ROUTES.ban, { address: "203.0.113.71", duration: "4h" }));
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["904"], 201));
		const calls = await call(host, TOOL_ROUTES.ban, { address: "203.0.113.71", duration: "4h" });
		within(calls);
		expect(calls.filter((c) => c === "httpFetch")).toHaveLength(3);
	});

	it("remove_ban with more decisions than one call removes, and delete_alert", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await respondLogin(host, 200, 2);
		const decisions = Array.from({ length: 12 }, (_, i) => ({ id: 100 + i, value: "203.0.113.14", duration: "1h", type: "ban" }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`, json([{ id: 1, decisions }]));
		for (const d of decisions) await host.http.respond(`${LAPI}/v1/decisions/${d.id}`, json({ nbDeleted: "1" }));
		const remove = await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.14" });
		within(remove);
		expect(remove.filter((c) => c === "httpFetch").length).toBeGreaterThan(4);

		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions: [{ id: 5, duration: "-10m" }] }));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ nbDeleted: "1" }));
		within(await call(host, TOOL_ROUTES.deleteAlert, { id: 625 }));
	});
});
