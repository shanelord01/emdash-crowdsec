import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { TOOL_ROUTES } from "../src/tools/load.js";
import { ADMIN, json, LAPI, newHost, respondLogin, sampleAlerts, tick, warmDns } from "./host.js";

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

interface ManifestTool {
	name: string;
	route: string;
	permission: string;
	destructive: boolean;
	outputSchema?: Record<string, unknown>;
}

function toolsOf(runtime: PluginRuntimeTestHost): ManifestTool[] {
	return (runtime.manifest as unknown as { mcp?: { tools: ManifestTool[] } }).mcp?.tools ?? [];
}

/**
 * Call a tool's route through the production dispatch and hold the answer
 * against the output schema the build wrote. The MCP server rejects an
 * answer that does not match, so a loader that drifts from its declaration
 * breaks the tool, not just a type.
 */
async function call(runtime: PluginRuntimeTestHost, route: string, body: Record<string, unknown> = {}) {
	const tool = toolsOf(runtime).find((t) => t.route === route);
	if (!tool?.outputSchema) throw new Error(`no tool with an output schema calls ${route}`);
	const response = await runtime.actions.routes.request(route, { body, user: ADMIN, headers: { "X-EmDash-Request": "1", "X-Real-IP": "198.51.100.7" } });
	expect(response.status).toBe(200);
	const result = ((await response.json()) as { data: unknown }).data;
	const parsed = z.fromJSONSchema({ ...tool.outputSchema }).safeParse(result);
	expect(parsed.error?.issues ?? []).toEqual([]);
	return result as Record<string, any>;
}

describe("the manifest's MCP tools", () => {
	it("each call a private route with the tool's permission: reads plugins:read, writes plugins:manage", async () => {
		host = await newHost();
		const manifest = host.manifest as unknown as { routes?: Array<string | { name: string; permission?: string; public?: boolean }> };
		const routes = new Map((manifest.routes ?? []).map((r) => (typeof r === "string" ? [r, { name: r }] : [r.name, r])));
		const tools = toolsOf(host);
		expect(tools.map((t) => t.name).sort()).toEqual(["active_decisions", "ban_ip", "delete_alert", "ip_alerts", "remove_ban", "security_summary", "top_threats"]);
		for (const tool of tools) {
			const route = routes.get(tool.route) as { permission?: string; public?: boolean } | undefined;
			expect(route, tool.name).toBeDefined();
			expect(route!.public, tool.name).not.toBe(true);
			expect(route!.permission, tool.name).toBe(tool.permission);
			const write = ["ban_ip", "remove_ban", "delete_alert"].includes(tool.name);
			expect(tool.permission, tool.name).toBe(write ? "plugins:manage" : "plugins:read");
			expect(tool.destructive, tool.name).toBe(write);
		}
	});
});

describe("answers match their declared schemas", () => {
	it("security_summary and top_threats, before any sync and after one", async () => {
		host = await newHost("demo");
		for (const days of [7, 30, 90]) await call(host, TOOL_ROUTES.summary, { days });
		await call(host, TOOL_ROUTES.top, {});
		await tick(host)();
		const summary = await call(host, TOOL_ROUTES.summary, { days: 7 });
		expect(summary.alerts).toBeGreaterThan(0);
		expect(summary.window.until).toMatch(/^\d{4}-\d\d-\d\d$/);
		const top = await call(host, TOOL_ROUTES.top, { days: 7, limit: 3 });
		expect(top.scenarios.length).toBeLessThanOrEqual(3);
		expect(top.scenarios.length).toBeGreaterThan(0);
	});

	it("active_decisions and ip_alerts, live, with ip_alerts keeping exact source matches only", async () => {
		host = await newHost("lapi");
		await respondLogin(host, 200, 2);
		await host.http.respond(`${LAPI}/v1/alerts?has_active_decision=true&simulated=false&limit=100`, json(sampleAlerts()));
		const decisions = await call(host, TOOL_ROUTES.decisions, { limit: 2 });
		expect(decisions).toMatchObject({ total: 5, truncated: true });
		expect(decisions.decisions).toHaveLength(2);

		const mixed = [...sampleAlerts(), { ...sampleAlerts()[0], id: 9, source: { value: "", ip: "" } }];
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&simulated=false&limit=50`, json(mixed));
		// Asked as IPv4-mapped IPv6, it searches the IPv4 form LAPI stores.
		const ip = await call(host, TOOL_ROUTES.ipAlerts, { address: "::ffff:203.0.113.14" });
		expect(ip.address).toBe("203.0.113.14");
		expect(ip.alerts.map((a: { id: number }) => a.id).sort()).toEqual([573, 574, 576, 625, 649, 662]);
	});

	it("the write tools, done and refused", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await warmDns(host);
		await call(host, TOOL_ROUTES.ban, { address: "10.0.0.1", duration: "4h" });
		await respondLogin(host, 200, 3);
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["905"], 201));
		expect(await call(host, TOOL_ROUTES.ban, { address: "203.0.113.80", duration: "1h", type: "captcha", note: "test" })).toMatchObject({ done: true });
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.80&has_active_decision=true&simulated=true&limit=50`, json([]));
		expect(await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.80" })).toMatchObject({ done: false });
		await host.http.respond(`${LAPI}/v1/alerts/1`, json(null, 404));
		expect(await call(host, TOOL_ROUTES.deleteAlert, { id: 1 })).toMatchObject({ done: false, message: "Alert 1 is not in CrowdSec any more, so it was taken off the list." });
	});

	it("the write tools' success paths: remove_ban and delete_alert done", async () => {
		host = await newHost("lapi", { allowChanges: true });
		await warmDns(host);
		await respondLogin(host, 200, 2);
		await host.http.respond(
			`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`,
			json([{ id: 1, decisions: [{ id: 11, value: "203.0.113.14", duration: "1h", type: "ban" }] }]),
		);
		await host.http.respond(`${LAPI}/v1/decisions/11`, json({ nbDeleted: "1" }));
		expect(await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.14" })).toMatchObject({ done: true, removed: 1, remaining: 0, value: "203.0.113.14" });
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions: [{ id: 5, duration: "-10m" }] }));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ nbDeleted: "1" }));
		expect(await call(host, TOOL_ROUTES.deleteAlert, { id: 625 })).toMatchObject({ done: true, message: "Deleted alert 625." });
	});
});
