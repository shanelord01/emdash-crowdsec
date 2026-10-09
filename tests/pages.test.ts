import { validateBlockResponse, validateBlocks } from "@emdash-cms/blocks/server";
import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SyncState } from "../src/sync/scheduler.js";
import { ALERTS_PATH, DECISIONS_PATH, RANGE_ACTION, SECURITY_PATH, SETUP_ACTION, WIDGET_REFRESH } from "../src/ui/ids.js";
import { renderWidget } from "../src/ui/widget.js";
import { USER_AGENT } from "../src/version.js";
import { xid } from "../src/ui/explorer.js";
import { DEFAULT_VIEW, withView, type ExplorerView } from "../src/explorer/model.js";

const VIEW: ExplorerView = { ...DEFAULT_VIEW, f: {} };
import { renderSecurity } from "../src/ui/security.js";
import { emptyDay } from "../src/store/rows.js";
import { alertById, seedStore } from "./seed.js";
import { ADMIN, EDITOR, hostSettings, seededHost, json, LAPI, newHost, respondLogin, respondSearch, sampleAlerts, tick, ZONE } from "./host.js";

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

describe("with stored alerts", () => {
	it("renders every surface, empty and synced, for an editor", async () => {
		host = await newHost("lapi");
		for (const response of [
			await host.admin.loadWidget("security", { user: EDITOR }),
			await host.admin.loadPage(SECURITY_PATH, { user: EDITOR }),
			await host.admin.loadPage(ALERTS_PATH, { user: EDITOR }),
		]) {
			expectValid(host, response);
		}

		await seedStore(host, hostSettings, Date.now() - 7 * 86_400_000, new Date());
		const widget = await host.admin.loadWidget("security", { user: EDITOR });
		expectValid(host, widget);
		expect(text(widget)).toMatch(/Alerts, last 24 hours/);
		expect(text(widget)).toMatch(/Synced/);

		for (const range of [7, 30, 90]) {
			const page = await host.admin.act(SECURITY_PATH, RANGE_ACTION, { value: range, user: EDITOR });
			expectValid(host, page);
			expect(text(page)).toContain(`Alerts, last ${range} days`);
		}

		const alerts = await host.admin.loadPage(ALERTS_PATH, { user: EDITOR });
		expectValid(host, alerts);
		expect(text(alerts)).toContain("cs:x:groups");

		const waf = await host.admin.act(ALERTS_PATH, xid("kind:waf", withView(VIEW, { k: "waf", g: false })), { user: EDITOR });
		expectValid(host, waf);
		const rows = (waf.blocks.find((b) => b.block_id === "cs:x:alerts") as unknown as { rows: Array<{ scenario: string }> }).rows;
		expect(rows.length).toBeGreaterThan(0);
		expect(rows.every((r) => r.scenario.endsWith("(WAF)"))).toBe(true);

		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json(sampleAlerts()));
		const decisions = await host.admin.loadPage(DECISIONS_PATH, { user: EDITOR });
		expectValid(host, decisions);
		expect(text(decisions)).toContain("cs:decisions:table");
	});

	it("schedules the sync from a dashboard visit, and Refresh asks for a step", async () => {
		host = await newHost("lapi");
		await host.admin.loadWidget("security");
		const names = (await host.inspect.scheduledTasks()).map((t) => String(t.name));
		expect(names).toEqual(expect.arrayContaining(["sync", "reconcile"]));
		const refreshed = await host.admin.act("widget:security", WIDGET_REFRESH);
		expect(refreshed.toast).toMatchObject({ type: "success" });
		expect((await host.inspect.scheduledTasks()).map((t) => String(t.name))).toContain("refresh");
	});
});

/** Every action id in an answer, and how many JSON nodes it holds: the host refuses more than 2,000. */
function inspectBlocks(blocks: unknown) {
	const ids: string[] = [];
	let nodes = 0;
	const walk = (v: unknown) => {
		nodes++;
		if (Array.isArray(v)) v.forEach(walk);
		else if (v && typeof v === "object") {
			for (const [key, value] of Object.entries(v)) {
				if ((key === "action_id" || key === "page_action_id") && typeof value === "string") ids.push(value);
				walk(value);
			}
		}
	};
	walk(blocks);
	return { ids, nodes };
}

describe("the Alerts explorer", () => {
	it("renders every view inside the host's limits, with an action id of its own on every control", async () => {
		host = await seededHost({ retentionDays: 400 }, 120);
		const views: ExplorerView[] = [];
		for (const p of ["1h", "24h", "3d", "7d", "30d", "ret"] as const) {
			views.push(withView(VIEW, { p }), withView(VIEW, { p, g: false }), withView(VIEW, { p, b: ["country", "scenario"] }));
		}
		views.push(
			withView(VIEW, { k: "waf" }),
			withView(VIEW, { f: { cn: "NL", bh: "http-scan" } }),
			withView(VIEW, { f: { ip: "203.0.113.0/24" }, b: ["as", "path"] }),
			withView(VIEW, { p: "3d", o: 1 }),
			withView(VIEW, { p: "ret", d: "203.0.113.10" }),
			withView(VIEW, { n: 1 }),
		);
		for (const view of views) {
			for (const user of [EDITOR, ADMIN]) {
				const page = await host.admin.act(ALERTS_PATH, xid("x", view), { user });
				expectValid(host, page);
				const { ids, nodes } = inspectBlocks(page.blocks);
				expect(nodes).toBeLessThan(1900);
				expect(ids.length - new Set(ids).size).toBe(0);
			}
		}
	});

	it("filters every panel and the table by an address range, and shows only that range's addresses", async () => {
		host = await seededHost();
		const page = await host.admin.act(ALERTS_PATH, xid("x", withView(VIEW, { f: { ip: "198.51.100.0/24" } })), { user: EDITOR });
		const groups = (page.blocks.find((b) => b.block_id === "cs:x:groups") as unknown as { rows: Array<{ source: string }> }).rows;
		expect(groups.length).toBeGreaterThan(0);
		expect(groups.every((g) => g.source.startsWith("198.51.100."))).toBe(true);
		const panel = (page.blocks.find((b) => b.block_id === "cs:x:panels") as unknown as { columns: Array<Array<{ block_id?: string; rows?: Array<{ value: string }> }>> }).columns[0]!;
		const top = panel.find((b) => b.block_id === "cs:x:panel0")!.rows!;
		expect(top.filter((r) => r.value !== "Other").every((r) => r.value.startsWith("198.51.100."))).toBe(true);
	});

	it("applies the filter form, shows each filter as a chip, and drops one when its chip is pressed", async () => {
		host = await seededHost();
		const filtered = await host.admin.submit(ALERTS_PATH, xid("filter", VIEW), { ip: "", cn: "NL", sc: "", bh: "http-scan", as: "", tg: "" }, { user: EDITOR });
		const chips = filtered.blocks.find((b) => b.block_id === "cs:x:chips") as unknown as { elements: Array<{ action_id: string; label: string }> };
		expect(chips.elements.map((e) => e.label)).toEqual(["Country: Netherlands ✕", "Behaviour: HTTP scan ✕"]);
		const dropped = await host.admin.act(ALERTS_PATH, chips.elements[0]!.action_id, { user: EDITOR });
		const left = dropped.blocks.find((b) => b.block_id === "cs:x:chips") as unknown as { elements: Array<{ label: string }> };
		expect(left.elements.map((e) => e.label)).toEqual(["Behaviour: HTTP scan ✕"]);

		// An address that does not parse is dropped, never searched for.
		const bad = await host.admin.submit(ALERTS_PATH, xid("filter", VIEW), { ip: "not-an-ip" }, { user: EDITOR });
		expect(bad.blocks.find((b) => b.block_id === "cs:x:chips")).toBeUndefined();
	});

	it("switches a panel's breakdown from its menu", async () => {
		host = await seededHost();
		const page = await host.admin.act(ALERTS_PATH, xid("dim1", VIEW), { value: "country", user: EDITOR });
		const panels = JSON.stringify(page.blocks.find((b) => b.block_id === "cs:x:panels"));
		expect(panels).toContain('"text":"Country"');
		expect(panels).not.toContain('"text":"Behaviour"');
	});

	it("shows the engine that raised each alert when several report to one LAPI, by name from the setting", async () => {
		host = await seededHost({ engineNames: "edge-01 = Edge, web-02 = Web" });
		const each = await host.admin.act(ALERTS_PATH, xid("x", withView(VIEW, { p: "7d", g: false, b: ["engine", "behaviour"] })), { user: EDITOR });
		expectValid(host, each);
		const text = JSON.stringify(each.blocks);
		expect(text).toContain('"label":"Engine"');
		expect(text).toContain("Edge");
		// The long generated id of the third engine, cut to 8 characters.
		expect(text).toContain("7f3c9a1e…");
		const rows = (each.blocks.find((b) => b.block_id === "cs:x:alerts") as unknown as { rows: Array<{ engine: string }> }).rows;
		expect(new Set(rows.map((r) => r.engine)).size).toBeGreaterThan(1);

		const web = await host.admin.act(ALERTS_PATH, xid("x", withView(VIEW, { p: "7d", g: false, f: { en: "web-02" } })), { user: EDITOR });
		const webRows = (web.blocks.find((b) => b.block_id === "cs:x:alerts") as unknown as { rows: Array<{ engine: string }> }).rows;
		expect(webRows.length).toBeGreaterThan(0);
		expect(webRows.every((r) => r.engine === "Web")).toBe(true);
		expect(JSON.stringify(web.blocks)).toContain("Engine: Web ✕");

		const grouped = await host.admin.act(ALERTS_PATH, xid("x", withView(VIEW, { p: "7d" })), { user: EDITOR });
		expect(JSON.stringify(grouped.blocks)).toMatch(/seen by [23] engines/);

		const security = await host.admin.act(SECURITY_PATH, RANGE_ACTION, { value: 7, user: EDITOR });
		expect(JSON.stringify(security.blocks)).toContain("cs:chart:engines");
	});

	it("shows an alert's live detail with its events, and the local hints on an address", async () => {
		host = await seededHost();
		const each = await host.admin.act(ALERTS_PATH, xid("x", withView(VIEW, { g: false })), { user: EDITOR });
		const detailId = JSON.stringify(each.blocks).match(/"action_id":"(cs:x:al:\d+\|[^"]*)"/)![1]!;
		const id = Number(detailId.match(/^cs:x:al:(\d+)/)![1]);
		await respondLogin(host);
		await host.http.respond(`${LAPI}/v1/alerts/${id}`, json(alertById(id, new Date())));
		const detail = await host.admin.act(ALERTS_PATH, detailId, { user: EDITOR });
		expectValid(host, detail);
		const text = JSON.stringify(detail.blocks);
		expect(text).toContain("cs:x:alevents");
		expect(text).toContain("User agent");
		// The kind is the plugin's own label, never LAPI's raw value ("crowdsec").
		expect(text).toMatch(/"label":"Kind","value":"(WAF|Bot challenge|Behaviour|Manual)"/);
		expect(text).toContain("cs:x:aldecisions");
		// The detail names the engine with its whole machine id.
		expect(text).toMatch(/"label":"Engine","value":"(edge-01|web-02|7f3c9a1e2b8d4c6fa0e5b9d2c4f81a37Qx2LmN8pRt5VwZ)"/);

		const groups = await host.admin.act(ALERTS_PATH, xid("x", VIEW), { user: EDITOR });
		expect(JSON.stringify(groups.blocks)).toMatch(/Banned now/);
	});
});

describe("an alert's detail against a LAPI", () => {
	it("caps the decision and meta rows, and never shows a community blocklist alert", async () => {
		host = await newHost("lapi");
		await respondLogin(host, 200, 2);
		const decisions = Array.from({ length: 500 }, (_, i) => ({ id: 9000 + i, type: "ban", duration: "3h", value: "203.0.113.14", origin: "crowdsec", scenario: "x" }));
		const meta = Array.from({ length: 60 }, (_, i) => ({ key: `k${i}`, value: "v" }));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions, meta }));
		const page = await host.admin.act(ALERTS_PATH, xid("al", { ...VIEW, al: 625 }), { user: EDITOR });
		expectValid(host, page);
		const rows = (id: string) => (page.blocks.find((b) => b.block_id === id) as unknown as { rows: unknown[] }).rows;
		expect(rows("cs:x:aldecisions")).toHaveLength(20);
		expect(rows("cs:x:almeta")).toHaveLength(20);
		expect(JSON.stringify(page.blocks)).toContain("And 480 more.");
		expect(inspectBlocks(page.blocks).nodes).toBeLessThan(1900);

		const capi = Array.from({ length: 3000 }, (_, i) => ({ id: 20000 + i, type: "ban", duration: "100h", value: `198.51.${i >> 8}.${i & 255}`, origin: "CAPI", scenario: "http:scan" }));
		await host.http.respond(`${LAPI}/v1/alerts/700`, json({ id: 700, scenario: "update : +3000/-0 IPs", source: { scope: "crowdsecurity/community-blocklist" }, decisions: capi }));
		const blocked = await host.admin.act(ALERTS_PATH, xid("al", { ...VIEW, al: 700 }), { user: EDITOR });
		expectValid(host, blocked);
		expect(JSON.stringify(blocked.blocks)).toContain("Alert 700 is not one of this site's alerts in CrowdSec.");
		expect(blocked.blocks.find((b) => b.block_id === "cs:x:aldecisions")).toBeUndefined();
	});
});

describe("the setup check", () => {
	it("asks for the LAPI settings on an install that used demo data, which 0.1.1 no longer has", async () => {
		host = await newHost("lapi");
		await host.fixtures.plugin.setting("source", "demo");
		for (const key of ["lapiUrl", "machineId", "machinePassword"]) await host.fixtures.plugin.setting(key, "");
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		expectValid(host, response);
		expect(text(response)).toContain("CrowdSec is not configured yet: add the LAPI URL, the machine ID, and the machine password");
		expect(host.http.requests()).toEqual([]);
		const widget = await host.admin.loadWidget("security", { user: EDITOR });
		expectValid(host, widget);
	});

	it("names a refused login and the User-Agent rule with it", async () => {
		host = await newHost("lapi");
		await respondLogin(host, 401);
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		expectValid(host, response);
		const checks = (response.blocks.find((b) => b.block_id === "cs:setup:checks") as { rows: Array<Record<string, string>> }).rows;
		expect(checks.find((r) => r.check === "Login")).toMatchObject({ status: "Problem" });
		expect(checks.find((r) => r.check === "User-Agent")?.detail).toContain(USER_AGENT);
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
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`, json(alerts));
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
		const blocks = renderSecurity({ state, zone: ZONE, range: 7, days: [day], traffic: [], metrics: null, metricsOn: false, now: NOW, lang: "en" });
		expect(validateBlocks(blocks).valid).toBe(true);
		const chart = blocks.find((b) => b.block_id === "cs:chart:alerts") as unknown as { config: { chart_type: string; options: { xAxis: { data: string[] } } } };
		expect(chart.config.chart_type).toBe("custom");
		// 9 October in Sydney is the last label, though it is still 8 October in UTC.
		expect(chart.config.options.xAxis.data.at(-1)).toBe("9 Oct");
		expect(chart.config.options.xAxis.data).toHaveLength(7);
	});

	it("draws alerts by engine only when more than one engine raised alerts in the range", () => {
		const one = { ...emptyDay("2026-10-08", NOW), alerts: 3, waf: 3, machines: { "example-machine": 3 } };
		const single = renderSecurity({ state, zone: ZONE, range: 7, days: [one], traffic: [], metrics: null, metricsOn: false, now: NOW, lang: "en" });
		expect(single.find((b) => b.block_id === "cs:chart:engines")).toBeUndefined();
		const two = { ...one, machines: { "example-machine": 2, "3f9e2c7a51d84b0e9c6a2f1d8b7e4c05AbCdEfGhIjKlMnOp": 1 } };
		const many = renderSecurity({ state, zone: ZONE, range: 7, days: [two], traffic: [], metrics: null, metricsOn: false, now: NOW, lang: "en", engineNames: { "example-machine": "Edge" } });
		const chart = many.find((b) => b.block_id === "cs:chart:engines") as unknown as { config: { options: { yAxis: { data: string[] } } } };
		expect(chart.config.options.yAxis.data).toEqual(["Edge", "3f9e2c7a…"]);
	});

	it("shows the widget's comparison only once the store reaches back 48 hours", () => {
		const blocks = renderWidget({ state, zone: ZONE, now: NOW, lang: "en" });
		expect(validateBlocks(blocks).valid).toBe(true);
		expect(JSON.stringify(blocks)).toContain("no earlier period to compare yet");
		const later = renderWidget({ state: { ...state, gaps: [{ from: "2026-07-01T00:00:00Z", to: "2026-10-08T23:00:00Z" }] }, zone: ZONE, now: NOW, lang: "en" });
		expect(JSON.stringify(later)).toContain("Still reading history");
	});
});
