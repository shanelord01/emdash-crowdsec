import { validateBlockResponse, validateBlocks } from "@emdash-cms/blocks/server";
import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SyncState } from "../src/sync/scheduler.js";
import { ALERTS_PATH, ALERTS_VIEW, DECISIONS_PATH, RANGE_ACTION, SECURITY_PATH, SETUP_ACTION, WIDGET_REFRESH } from "../src/ui/ids.js";
import { renderWidget } from "../src/ui/widget.js";
import { renderSecurity } from "../src/ui/security.js";
import { emptyDay } from "../src/store/rows.js";
import { EDITOR, json, LAPI, newHost, respondLogin, respondSearch, sampleAlerts, tick, ZONE } from "./host.js";

/**
 * The widget and the pages through the real sandbox and route, each answer
 * checked by the host's own validator, the check that catches camelCase
 * Block Kit keys the renderer would silently ignore.
 */

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

function expectValid(runtime: PluginRuntimeTestHost, response: unknown) {
	const pages = (runtime.manifest.admin?.pages ?? []).map((page) => page.path);
	const result = validateBlockResponse(response, { pluginPagePaths: pages });
	if (!result.valid) throw new Error(result.errors.map((e) => `${e.path}: ${e.message}`).join("\n"));
}

const text = (response: { blocks: unknown[] }) => JSON.stringify(response.blocks);

describe("with demo data", () => {
	it("renders every surface, empty and synced, for an editor", async () => {
		host = await newHost("demo");
		for (const response of [
			await host.admin.loadWidget("security", { user: EDITOR }),
			await host.admin.loadPage(SECURITY_PATH, { user: EDITOR }),
			await host.admin.loadPage(ALERTS_PATH, { user: EDITOR }),
		]) {
			expectValid(host, response);
		}

		await tick(host)();
		const widget = await host.admin.loadWidget("security", { user: EDITOR });
		expectValid(host, widget);
		expect(text(widget)).toMatch(/Alerts, last 24 hours/);
		expect(text(widget)).toMatch(/Demo data, not real alerts/);

		for (const range of [7, 30, 90]) {
			const page = await host.admin.act(SECURITY_PATH, RANGE_ACTION, { value: range, user: EDITOR });
			expectValid(host, page);
			expect(text(page)).toContain(`Alerts, last ${range} days`);
		}

		const alerts = await host.admin.loadPage(ALERTS_PATH, { user: EDITOR });
		expectValid(host, alerts);
		expect(text(alerts)).toContain("cs:alerts:table");

		const waf = await host.admin.act(ALERTS_PATH, `${ALERTS_VIEW}|waf|`, { user: EDITOR });
		expectValid(host, waf);
		const rows = (waf.blocks.find((b) => b.block_id === "cs:alerts:table") as unknown as { rows: Array<{ kind: string }> }).rows;
		expect(rows.length).toBeGreaterThan(0);
		expect(new Set(rows.map((r) => r.kind))).toEqual(new Set(["WAF"]));

		const decisions = await host.admin.loadPage(DECISIONS_PATH, { user: EDITOR });
		expectValid(host, decisions);
		expect(text(decisions)).toContain("cs:decisions:table");
	});

	it("schedules the sync from a dashboard visit, and Refresh asks for a step", async () => {
		host = await newHost("demo");
		await host.admin.loadWidget("security");
		const names = (await host.inspect.scheduledTasks()).map((t) => String(t.name));
		expect(names).toEqual(expect.arrayContaining(["sync", "reconcile"]));
		const refreshed = await host.admin.act("widget:security", WIDGET_REFRESH);
		expect(refreshed.toast).toMatchObject({ type: "success" });
		expect((await host.inspect.scheduledTasks()).map((t) => String(t.name))).toContain("refresh");
	});
});

describe("the setup check", () => {
	it("names a refused login and the User-Agent rule with it", async () => {
		host = await newHost("lapi");
		await respondLogin(host, 401);
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		expectValid(host, response);
		const checks = (response.blocks.find((b) => b.block_id === "cs:setup:checks") as { rows: Array<Record<string, string>> }).rows;
		expect(checks.find((r) => r.check === "Login")).toMatchObject({ status: "Problem" });
		expect(checks.find((r) => r.check === "User-Agent")?.detail).toMatch(/emdash-crowdsec\/0\.1\.0/);
	});

	it("passes a working LAPI and looks up the ban protections when changes are on", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 3_600_000), limit: 1, simulated: false }), []);
		for (const name of ["www.example.test", "lapi.example.test"]) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 1, data: "198.51.100.10" }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({}));
		}
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		const checks = (response.blocks.find((b) => b.block_id === "cs:setup:checks") as { rows: Array<Record<string, string>> }).rows;
		for (const name of ["Login", "User-Agent", "Read access", "Ban protections"]) {
			expect(checks.find((r) => r.check === name)?.status, name).toBe("OK");
		}
		await expect(host.inspect.kv.get("sync.dns")).resolves.toMatchObject({ addresses: { "www.example.test": ["198.51.100.10"] } });
		// The check's fresh token is not saved over the cached one.
		await expect(host.inspect.kv.get("sync.session")).resolves.toBeNull();
	});

	it("names a LAPI URL on a private address", async () => {
		host = await newHost("lapi", { lapiUrl: "https://192.168.1.10:8080" });
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		expect(text(response)).toMatch(/private or internal address/);
		await host.dispose();
		host = await newHost("lapi", { lapiUrl: "http://lapi.example.test" });
		expect(text(await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 }))).toMatch(/plain HTTP, and the plugin only uses HTTPS/);
		expect(host.http.requests()).toEqual([]);
	});
});

describe("the Decisions page against a LAPI", () => {
	it("lists active decisions live, soonest to expire first, without write controls while changes are off", async () => {
		host = await newHost("lapi");
		await respondLogin(host);
		const alerts = sampleAlerts();
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&limit=100`, json(alerts));
		const page = await host.admin.loadPage(DECISIONS_PATH);
		expectValid(host, page);
		const table = page.blocks.find((b) => b.block_id === "cs:decisions:table") as unknown as { rows: Array<{ value: string; expires: string }>; columns: Array<{ key: string }> };
		expect(table.rows.map((r) => r.value)).toEqual(["203.0.113.14", "203.0.113.14", "203.0.113.14", "203.0.113.14", "203.0.113.10"]);
		expect(table.columns.map((c) => c.key)).not.toContain("remove");
		expect(text(page)).not.toContain("cs:ban:form");
	});
});

describe("rendering", () => {
	const NOW = new Date("2026-10-09T02:00:00Z");
	const state: SyncState = {
		head: NOW.toISOString(),
		gaps: [],
		// Stored history reaches back only a day, so there is no previous 24 hours to compare.
		floor: "2026-10-08T00:00:00Z",
		lastSync: NOW.toISOString(),
		hours: { "2026-10-09T01": { alerts: 5, waf: 2, bot: 1, behaviour: 2, manual: 0, scenarios: { a: 3, b: 2 } } },
		active: { bans: 3, decisions: 4, at: NOW.toISOString(), truncated: false },
	};

	it("draws daily charts on a category axis of local day labels, so no viewer sees a timestamp", () => {
		const day = { ...emptyDay("2026-10-08", NOW), alerts: 3, waf: 3 };
		const blocks = renderSecurity({ state, source: "lapi", zone: ZONE, range: 7, days: [day], now: NOW, lang: "en" });
		expect(validateBlocks(blocks).valid).toBe(true);
		const chart = blocks.find((b) => b.block_id === "cs:chart:alerts") as unknown as { config: { chart_type: string; options: { xAxis: { data: string[] } } } };
		expect(chart.config.chart_type).toBe("custom");
		// 9 October in Sydney is the last label, though it is still 8 October in UTC.
		expect(chart.config.options.xAxis.data.at(-1)).toBe("9 Oct");
		expect(chart.config.options.xAxis.data).toHaveLength(7);
	});

	it("shows the widget's comparison only once the store reaches back 48 hours", () => {
		const blocks = renderWidget({ state, source: "lapi", zone: ZONE, now: NOW, lang: "en" });
		expect(validateBlocks(blocks).valid).toBe(true);
		expect(JSON.stringify(blocks)).toContain("no earlier period to compare yet");
		const later = renderWidget({ state: { ...state, gaps: [{ from: "2026-07-01T00:00:00Z", to: "2026-10-08T23:00:00Z" }] }, source: "lapi", zone: ZONE, now: NOW, lang: "en" });
		expect(JSON.stringify(later)).toContain("Still reading history");
	});
});
