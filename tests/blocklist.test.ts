import { validateBlockResponse } from "@emdash-cms/blocks/server";
import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import { alertSearch } from "../src/lapi/client.js";
import { isBlocklistAlert } from "../src/lapi/blocklist.js";
import type { RawAlert } from "../src/lapi/types.js";
import type { AlertRow, DayRow } from "../src/store/rows.js";
import { activeOf, BLOCKLIST_KEY, DEFAULT_BATCH, runBlocklistCount, type SyncState } from "../src/sync/scheduler.js";
import { TOOL_ROUTES } from "../src/tools/load.js";
import { BAN_REVIEW, DECISIONS_PATH } from "../src/ui/ids.js";
import { bridgeCalls } from "./bridge-calls.js";
import { fakeCtx } from "./fake-ctx.js";
import { ADMIN, json, LAPI, newHost, respondLogin, respondSearch, sampleAlerts, setState, tick, warmDns, ZONE } from "./host.js";

/**
 * The community blocklist. LAPI returns its alerts unless asked not to:
 * on a live site one search with an active decision came back with 90
 * alerts and 24,023 decisions, 24,004 of them the blocklist's, in 3.7 MB.
 * They are not the site's own events, so they are left out of every read
 * but a lookup of one address, and shown as one count.
 */

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

const DATASET = `lapi|${LAPI}|false|${ZONE}`;

/** A community blocklist alert as LAPI answers it: an empty source and many decisions of origin CAPI. */
function capiAlert(id = 900, values = ["192.0.2.1", "192.0.2.2", "203.0.113.14"]): RawAlert {
	const at = new Date(Date.now() - 2 * 3_600_000).toISOString();
	return {
		id,
		scenario: "update : +3/-0 IPs",
		kind: "crowdsec",
		message: "",
		created_at: at,
		start_at: at,
		stop_at: at,
		events_count: 0,
		simulated: false,
		source: { scope: "crowdsecurity/community-blocklist", value: "" },
		decisions: values.map((value, i) => ({ id: 5000 + i, type: "ban", duration: "20h", origin: "CAPI", scenario: "http:scan", scope: "Ip", value })),
		meta: null,
		events: null,
	};
}

describe("searches", () => {
	it("leave the blocklists out unless one address is looked up or an origin is asked for", () => {
		const now = new Date("2026-10-09T00:00:00Z");
		expect(alertSearch({ activeOnly: true, limit: 100 }, now)).toContain("include_capi=false");
		expect(alertSearch({ scope: "Ip", value: "203.0.113.14", limit: 50, blocklists: "include" }, now)).not.toContain("include_capi");
		expect(alertSearch({ origin: "CAPI", activeOnly: true, limit: 1000 }, now)).toBe("has_active_decision=true&origin=CAPI&simulated=false&limit=1000");
	});

	it("know a blocklist alert by its decisions' origin or its source scope", () => {
		expect(isBlocklistAlert(capiAlert())).toBe(true);
		expect(isBlocklistAlert({ source: { scope: "lists:firehol" }, decisions: [] })).toBe(true);
		for (const alert of sampleAlerts()) expect(isBlocklistAlert(alert), String(alert.id)).toBe(false);
	});
});

describe("counts", () => {
	it("never count a blocklist ban as the site's own", () => {
		const active = activeOf([...sampleAlerts(), capiAlert()], new Date(), false);
		expect(active.bans).toBe(2); // 203.0.113.14 and 203.0.113.10, from the site's own alerts
	});

	it("are not changed by a blocklist alert the sync is sent anyway", async () => {
		host = await newHost("lapi", { retentionDays: 7 });
		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(Date.parse(new Date(now).toISOString()) - 0), limit: DEFAULT_BATCH }), []);
		const { floorOf } = await import("../src/sync/scheduler.js");
		await respondSearch(host, (now) => ({ since: new Date(floorOf({ retentionDays: 7, timeZone: ZONE }, now)), limit: DEFAULT_BATCH, simulated: false }), [...sampleAlerts(), capiAlert()]);

		await tick(host)();

		const alerts = await host.inspect.storage.list<AlertRow>("alerts");
		expect(alerts.map((a) => a.data.id)).not.toContain(900);
		const days = await host.inspect.storage.list<DayRow>("days");
		expect(days.reduce((n, d) => n + d.data.bans, 0)).toBe(5);
		expect(host.http.requests().filter((r) => r.url.includes("/v1/alerts?")).every((r) => r.url.includes("include_capi=false"))).toBe(true);
	});
});

describe("the blocklist count", () => {
	it("is counted daily in a task of its own and kept as one number", async () => {
		host = await newHost("lapi");
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&origin=CAPI&simulated=false&limit=1000`, json([capiAlert(), capiAlert(901, ["192.0.2.2", "192.0.2.3"])]));
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&origin=lists&simulated=false&limit=1000`, json([]));

		const calls = await bridgeCalls(tick(host, "blocklist"));

		expect(calls.length, calls.join(", ")).toBeLessThanOrEqual(10);
		expect(await host.inspect.kv.get(BLOCKLIST_KEY)).toMatchObject({ addresses: 4 });
		expect((await host.inspect.kv.get<SyncState>("sync.state"))?.lease).toBeUndefined();
	});

	it("is kept as too many to count when the answer is over 8 MiB", async () => {
		const fake = fakeCtx({
			settings: { source: "lapi", lapiUrl: LAPI, machineId: "m", machinePassword: "p", timeZone: ZONE },
			fetch: async (url) => {
				if (url.endsWith("/v1/watchers/login")) return json({ token: "t" });
				throw new Error("Plugin HTTP response body exceeds the 8388608 byte limit");
			},
		});
		expect(await runBlocklistCount(fake.ctx)).toMatchObject({ addresses: null });
	});

	it("shows on the Decisions page as one line, and its decisions are never rows", async () => {
		host = await newHost("lapi");
		await host.fixtures.plugin.kv(BLOCKLIST_KEY, { at: new Date().toISOString(), addresses: 24004 });
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json([...sampleAlerts(), capiAlert()]));
		const page = await host.admin.loadPage(DECISIONS_PATH);
		expect(validateBlockResponse(page, { pluginPagePaths: (host.manifest.admin?.pages ?? []).map((p) => p.path) }).valid).toBe(true);
		const text = JSON.stringify(page.blocks);
		expect(text).toContain("Also enforcing 24,004 addresses from the CrowdSec community blocklist");
		const table = page.blocks.find((b) => b.block_id === "cs:decisions:table") as unknown as { rows: Array<{ origin: string; value: string }> };
		expect(table.rows.every((r) => r.origin !== "CAPI")).toBe(true);
		expect(table.rows).toHaveLength(5);
	});

	it("is asked for by the dashboard until the first count is in", async () => {
		host = await newHost("lapi");
		await host.admin.loadWidget("security");
		const names = (await host.inspect.scheduledTasks()).map((t) => String(t.name));
		expect(names).toEqual(expect.arrayContaining(["blocklist", "blocklist-now"]));
	});
});

describe("a lookup of one address", () => {
	const lookup = (value: string, active: boolean) =>
		`${LAPI}/v1/alerts?scope=Ip&value=${value}${active ? "&has_active_decision=true&simulated=true" : "&simulated=false"}&limit=${active ? 50 : 50}`;

	it("ip_alerts says the address is on the blocklist, without listing the blocklist alert", async () => {
		host = await newHost("lapi");
		await respondLogin(host);
		await host.http.respond(lookup("203.0.113.14", false), json([...sampleAlerts().filter((a) => a.source?.value === "203.0.113.14"), capiAlert()]));
		const response = await host.actions.routes.request(TOOL_ROUTES.ipAlerts, { body: { address: "203.0.113.14" }, user: ADMIN, headers: { "X-EmDash-Request": "1" } });
		const { data } = (await response.json()) as { data: { alerts: Array<{ id: number }>; communityBlocklist: Array<{ origin: string }> } };
		expect(data.alerts.map((a) => a.id)).not.toContain(900);
		expect(data.communityBlocklist).toEqual([expect.objectContaining({ origin: "CAPI", scenario: "http:scan", type: "ban" })]);
	});

	it("remove_ban leaves a blocklist decision alone and says why", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await warmDns(host);
		await respondLogin(host);
		await host.http.respond(lookup("192.0.2.1", true), json([capiAlert()]));
		const response = await host.actions.routes.request(TOOL_ROUTES.removeBan, { body: { address: "192.0.2.1" }, user: ADMIN, headers: { "X-EmDash-Request": "1" } });
		const { data } = (await response.json()) as { data: { done: boolean; message: string } };
		expect(data.done).toBe(false);
		expect(data.message).toMatch(/only by the CrowdSec community blocklist/);
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("the ban review says when the blocklist already blocks the address", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await warmDns(host);
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=20`, json([capiAlert()]));
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json([]));
		const review = await host.admin.submit(DECISIONS_PATH, BAN_REVIEW, { value: "203.0.113.14", duration: "4h", type: "ban", note: "" });
		expect(JSON.stringify(review.blocks)).toContain("The CrowdSec community blocklist already blocks it.");
	});
});
