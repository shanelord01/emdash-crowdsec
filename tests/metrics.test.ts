import { validateBlockResponse, validateBlocks } from "@emdash-cms/blocks/server";
import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { parsePrometheus } from "../src/metrics/prom.js";
import { deltaOf, demoMetricsText, discarded, sampleOf } from "../src/metrics/sample.js";
import type { TrafficDay } from "../src/store/rows.js";
import { METRICS_KEY, runMetrics, type MetricsState } from "../src/sync/scheduler.js";
import { TOOL_ROUTES } from "../src/tools/load.js";
import { SECURITY_PATH, SETUP_ACTION } from "../src/ui/ids.js";
import { rangeActionId, renderSecurity } from "../src/ui/security.js";
import { bridgeCalls } from "./bridge-calls.js";
import { fakeCtx } from "./fake-ctx.js";
import { ADMIN, newHost, respondLogin, tick, ZONE } from "./host.js";
import engineText from "./fixtures/metrics-engine.txt?raw";
import firewallText from "./fixtures/metrics-firewall.txt?raw";

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

const ENGINE = "https://lapi.example.test/crowdsec-lapi/metrics/engine";
const FIREWALL = "https://lapi.example.test/crowdsec-lapi/metrics/firewall";
const text = (body: string, status = 200) => new Response(body, { status, headers: { "Content-Type": "text/plain; version=0.0.4" } });

describe("the Prometheus parser, on real answers", () => {
	it("keeps only the series the charts read, and skips histograms and the rest", () => {
		const engine = parsePrometheus(engineText);
		expect(new Set(engine.map((s) => s.name))).toEqual(
			new Set([
				"cs_active_decisions",
				"cs_appsec_reqs_total",
				"cs_appsec_block_total",
				"cs_appsec_challenge_requested_total",
				"cs_appsec_challenge_submitted_total",
				"cs_appsec_challenge_accepted_total",
				"cs_appsec_challenge_rejected_total",
				"cs_appsec_challenge_exempt_total",
				"cs_parser_hits_total",
			]),
		);
		expect(engine.find((s) => s.name === "cs_appsec_reqs_total")).toEqual({
			name: "cs_appsec_reqs_total",
			labels: { appsec_engine: "127.0.0.1:7422/", source: "127.0.0.1" },
			value: 12533,
		});
		const firewall = parsePrometheus(firewallText);
		expect(firewall.find((s) => s.name === "fw_bouncer_processed_bytes" && s.labels.ip_type === "ipv4")?.value).toBe(11150779);
	});

	it("reads escaped label values and skips lines it cannot read", () => {
		const parsed = parsePrometheus(['cs_appsec_block_total{a="x\\"y",b="z"} 3', "cs_appsec_block_total{broken 4", "cs_appsec_block_total NaN", "# TYPE x counter"].join("\n"));
		expect(parsed).toEqual([{ name: "cs_appsec_block_total", labels: { a: 'x"y', b: "z" }, value: 3 }]);
	});

	it("sums each counter by origin and keeps the active decisions by source", () => {
		const sample = sampleOf(parsePrometheus(engineText), parsePrometheus(firewallText), new Date());
		expect(sample.counters).toMatchObject({
			"drop.packets.detections": 8,
			"drop.packets.community": 0,
			"drop.bytes.detections": 320,
			"proc.packets": 1907,
			"as.reqs": 12533,
			"as.blocks": 199,
			"ch.requested": 6952,
			"ch.submitted": 100,
			"ch.accepted": 37,
		});
		expect(sample.gauges?.bansByOrigin).toEqual({ community: 23885, detections: 20, manual: 0, other: 0 });
		expect(sample.gauges?.communityReasons["http:scan"]).toBe(20919);
	});
});

describe("differences between samples", () => {
	it("count a counter that went down as reset, from its new value", () => {
		expect(deltaOf({ a: 100, b: 100 }, { a: 130, b: 30 })).toEqual({ a: 30, b: 30 });
	});

	it("count a new key from zero only when its source answered last time", () => {
		expect(deltaOf({ a: 1 }, { a: 1, b: 50 }, () => true)).toEqual({ b: 50 });
		expect(deltaOf({ a: 1 }, { a: 1, b: 50 }, () => false)).toEqual({});
	});
});

describe("the sampler", () => {
	const settings = { source: "lapi", lapiUrl: "https://lapi.example.test/crowdsec-lapi", machineId: "m", machinePassword: "p", timeZone: ZONE, engineMetricsUrl: ENGINE, firewallMetricsUrl: FIREWALL };
	const fw = (dropped: number) => `fw_bouncer_dropped_packets{ip_type="ipv4",origin="CAPI"} ${dropped}\nfw_bouncer_processed_packets{ip_type="ipv4"} ${dropped * 10}`;

	it("sets a baseline first, then stores what was counted on the local day, across a reset", async () => {
		let answer = fw(1000);
		let firewallDown = false;
		const fake = fakeCtx({
			settings,
			fetch: async (url) => {
				if (url === FIREWALL) {
					if (firewallDown) return text("down", 502);
					return text(answer);
				}
				return text(engineText);
			},
		});
		// 8:15 am in Sydney on 27 September, 2026-09-26 in UTC.
		const at = (minutes: number) => new Date(Date.parse("2026-09-26T22:15:00Z") + minutes * 60_000);

		expect(await runMetrics(fake.ctx, at(0))).toMatchObject({ ok: true, baseline: true });
		expect(fake.rows("traffic").size).toBe(0);

		answer = fw(1300);
		await runMetrics(fake.ctx, at(15));
		const day = fake.rows("traffic").get("2026-09-27") as TrafficDay;
		expect(day.counters["drop.packets.community"]).toBe(300);
		expect(fake.rows("traffic").has("2026-09-26")).toBe(false);

		// The bouncer restarted: its counter starts again from zero.
		answer = fw(40);
		await runMetrics(fake.ctx, at(30));
		expect((fake.rows("traffic").get("2026-09-27") as TrafficDay).counters["drop.packets.community"]).toBe(340);

		// Down, then back: nothing is counted while it is down, and its first answer after counts from the last value it had.
		firewallDown = true;
		await runMetrics(fake.ctx, at(45));
		firewallDown = false;
		answer = fw(90);
		await runMetrics(fake.ctx, at(60));
		expect((fake.rows("traffic").get("2026-09-27") as TrafficDay).counters["drop.packets.community"]).toBe(390);
	});

	it("does not count a source's whole history when it first answers after the baseline", async () => {
		let firewallUp = false;
		const fake = fakeCtx({
			settings,
			fetch: async (url) => (url === FIREWALL ? (firewallUp ? text(fw(50_000)) : text("", 502)) : text(engineText)),
		});
		await runMetrics(fake.ctx, new Date("2026-10-09T00:00:00Z"));
		firewallUp = true;
		await runMetrics(fake.ctx, new Date("2026-10-09T00:15:00Z"));
		const day = fake.rows("traffic").get("2026-10-09") as TrafficDay | undefined;
		expect(day?.counters["drop.packets.community"] ?? 0).toBe(0);
	});

	it("starts a new baseline when the URLs or the zone change", async () => {
		const fake = fakeCtx({ settings, fetch: async (url) => text(url === FIREWALL ? fw(10) : engineText) });
		await runMetrics(fake.ctx, new Date("2026-10-09T00:00:00Z"));
		const other = fakeCtx({ settings: { ...settings, timeZone: "Europe/Berlin" }, fetch: async (url) => text(url === FIREWALL ? fw(500) : engineText) });
		other.setState(undefined);
		expect(await runMetrics(other.ctx, new Date("2026-10-09T00:15:00Z"))).toMatchObject({ baseline: true });
	});
});

describe("the sampler in the sandbox", () => {
	it("reads both endpoints with the plugin's User-Agent, within seven bridge calls", async () => {
		host = await newHost("lapi", { engineMetricsUrl: ENGINE, firewallMetricsUrl: FIREWALL });
		for (let i = 0; i < 2; i++) {
			await host.http.respond(ENGINE, text(engineText));
			await host.http.respond(FIREWALL, text(firewallText));
		}
		within(await bridgeCalls(tick(host, "metrics")));
		const calls = await bridgeCalls(tick(host, "metrics"));
		within(calls, 7);
		expect(host.http.requests().every((r) => r.headers["user-agent"]?.startsWith("emdash-crowdsec/"))).toBe(true);
		await expect(host.inspect.kv.get<MetricsState>(METRICS_KEY)).resolves.toMatchObject({ gauges: { bansByOrigin: { community: 23885 } } });
	});

	it("names each metrics URL's state on the setup check", async () => {
		host = await newHost("lapi", { engineMetricsUrl: ENGINE, firewallMetricsUrl: "http://lapi.example.test/metrics" });
		await respondLogin(host, 401);
		await host.http.respond(ENGINE, text("<html>challenge</html>"));
		const response = await host.admin.act(SECURITY_PATH, SETUP_ACTION, { value: 30 });
		const rows = (response.blocks.find((b) => b.block_id === "cs:setup:checks") as unknown as { rows: Array<Record<string, string>> }).rows;
		expect(rows.find((r) => r.check === "Engine metrics")).toMatchObject({ status: "Problem", detail: expect.stringMatching(/web page instead of Prometheus/) });
		expect(rows.find((r) => r.check === "Firewall metrics")).toMatchObject({ status: "Problem", detail: expect.stringMatching(/plain HTTP/) });
	});
});

function within(calls: string[], limit = 10) {
	expect(calls.length, calls.join(", ")).toBeLessThanOrEqual(limit);
}

describe("the traffic charts", () => {
	const NOW = new Date("2026-10-09T02:00:00Z");
	const metrics: MetricsState = {
		source: "x",
		last: {},
		at: NOW.toISOString(),
		since: "2026-09-01T00:00:00Z",
		hours: { "2026-10-09T01": { "drop.packets.community": 40, "drop.packets.detections": 5, "proc.packets": 900, "as.reqs": 300, "as.blocks": 4 } },
		gauges: { bansByOrigin: { community: 23885, detections: 20, manual: 1, other: 0 }, communityReasons: { "http:scan": 20919, "ssh:bruteforce": 2501 } },
	};
	const trafficDay = (date: string, packets: number): TrafficDay => ({
		date,
		counters: { "drop.packets.community": packets, "drop.packets.detections": 7, "drop.bytes.community": packets * 64, "proc.packets": packets * 20, "as.reqs": 500, "as.blocks": 9, "ch.requested": 60, "ch.accepted": 11 },
		samples: 96,
		updatedAt: "",
	});
	const state = { head: NOW.toISOString(), gaps: [], floor: "2026-07-01T00:00:00Z", lastSync: NOW.toISOString(), hours: { "2026-10-09T01": { alerts: 5, bans: 2, waf: 2, bot: 1, behaviour: 2, manual: 0, scenarios: {} } } };

	function actionIds(blocks: unknown): string[] {
		return [...JSON.stringify(blocks).matchAll(/"action_id":"([^"]+)"/g)].map((m) => m[1]!);
	}

	it("draw discarded traffic by origin, its share, web requests, the challenge and bans by source, each with its series line", () => {
		const blocks = renderSecurity({
			state,
			source: "lapi",
			zone: ZONE,
			range: 7,
			days: [{ date: "2026-10-09", alerts: 3, waf: 1, bot: 1, behaviour: 1, manual: 0, decisions: 1, bans: 1, scenarios: { a: 3 }, countries: { NL: 2, DE: 1 }, asNames: {}, paths: {}, ips: {}, seen: [], updatedAt: "" }],
			traffic: [trafficDay("2026-10-08", 26_000), trafficDay("2026-10-09", 500)],
			metrics,
			metricsOn: true,
			now: NOW,
			lang: "en",
		});
		expect(validateBlocks(blocks).valid).toBe(true);
		const json = JSON.stringify(blocks);
		for (const id of ["cs:chart:discarded", "cs:meter:share", "cs:chart:requests", "cs:chart:challenge", "cs:chart:sources", "cs:chart:countries", "cs:chart:alerts"]) {
			expect(json, id).toContain(`"block_id":"${id}"`);
		}
		expect(json).toContain("Malicious traffic discarded");
		expect(json).toContain('"value":"26.5K"'); // 26,000 + 500 packets
		expect(json).toContain("Blue: Community blocklist · Yellow: Your detections");
		expect(json).toContain('"Netherlands"');
		const ids = actionIds(blocks);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it("show the last 24 hours by local hour", () => {
		const blocks = renderSecurity({ state, source: "lapi", zone: ZONE, range: 1, days: [], traffic: [], metrics, metricsOn: true, now: NOW, lang: "en" });
		expect(validateBlocks(blocks).valid).toBe(true);
		const chart = blocks.find((b) => b.block_id === "cs:chart:discarded") as unknown as { config: { options: { xAxis: { data: string[] } } } };
		// 02:00 UTC is 13:00 in Sydney: the last hour is 13:00, the first 14:00 the day before.
		expect(chart.config.options.xAxis.data.at(-1)).toBe("13:00");
		expect(chart.config.options.xAxis.data).toHaveLength(24);
		expect(JSON.stringify(blocks)).toContain(`"action_id":"${rangeActionId(1)}"`);
	});
});

describe("demo data", () => {
	it("generates metrics that grow over time and render on the Security page", async () => {
		const a = sampleOf(parsePrometheus(demoMetricsText("engine", new Date("2026-10-09T00:00:00Z"))), parsePrometheus(demoMetricsText("firewall", new Date("2026-10-09T00:00:00Z"))), new Date());
		const b = sampleOf(parsePrometheus(demoMetricsText("engine", new Date("2026-10-09T01:00:00Z"))), parsePrometheus(demoMetricsText("firewall", new Date("2026-10-09T01:00:00Z"))), new Date());
		const delta = deltaOf(a.counters, b.counters);
		expect(discarded(delta, "packets").total).toBeGreaterThan(50);
		expect(delta["as.reqs"]).toBeGreaterThan(100);

		host = await newHost("demo");
		await tick(host, "metrics")();
		const page = await host.admin.loadPage(SECURITY_PATH);
		expect(validateBlockResponse(page, { pluginPagePaths: (host.manifest.admin?.pages ?? []).map((p) => p.path) }).valid).toBe(true);
		expect(JSON.stringify(page.blocks)).toContain("Malicious traffic discarded");
	});
});

describe("traffic_summary", () => {
	it("answers in its declared schema, within the budget", async () => {
		host = await newHost("demo");
		const today = new Date().toISOString().slice(0, 10);
		await host.fixtures.plugin.storage("traffic", today, { date: today, counters: { "drop.packets.community": 100, "drop.bytes.community": 6400, "proc.packets": 1000, "as.reqs": 50, "as.blocks": 2 }, samples: 4, updatedAt: "" });
		await host.fixtures.plugin.kv(METRICS_KEY, { source: "x", last: {}, at: "", since: "2026-01-01T00:00:00Z", hours: {}, gauges: { bansByOrigin: { community: 9, detections: 1, manual: 0, other: 0 }, communityReasons: {} } });
		const tool = (host.manifest as unknown as { mcp: { tools: Array<{ route: string; outputSchema: Record<string, unknown> }> } }).mcp.tools.find((t) => t.route === TOOL_ROUTES.traffic)!;
		let data: unknown;
		const calls = await bridgeCalls(async () => {
			const response = await host!.actions.routes.request(TOOL_ROUTES.traffic, { body: { days: 7 }, user: ADMIN, headers: { "X-EmDash-Request": "1" } });
			data = ((await response.json()) as { data: unknown }).data;
		});
		within(calls);
		const parsed = z.fromJSONSchema({ ...tool.outputSchema }).safeParse(data);
		expect(parsed.error?.issues ?? []).toEqual([]);
		expect(data).toMatchObject({ enabled: true, discarded: { packets: 100 }, share: 0.1, activeByOrigin: { community: 9 } });
	});
});
