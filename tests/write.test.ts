import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TOOL_ROUTES } from "../src/tools/load.js";
import { BAN_CONFIRM, BAN_REVIEW, DECISIONS_PATH, DECISIONS_REMOVE, ALERTS_PATH } from "../src/ui/ids.js";
import { xid } from "../src/ui/explorer.js";
import { DEFAULT_VIEW } from "../src/explorer/model.js";

const VIEW = { ...DEFAULT_VIEW, f: {} };
import { ADMIN, EDITOR, expectUserAgent, json, LAPI, newHost, respondLogin, sampleAlerts, warmDns } from "./host.js";

/**
 * Every write path and every refusal, through the production route
 * dispatch: the route's permission, the CSRF header, the user and the
 * request's own headers, as a browser or an MCP client would send them.
 */

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

const OWN = "198.51.100.7";

async function writeHost(extra: Record<string, unknown> = {}) {
	const runtime = await newHost("lapi", { allowChanges: true, protectedAddresses: "192.0.2.0/24", ...extra });
	// Every invocation that needs LAPI logs in once.
	await respondLogin(runtime, 200, 4);
	await warmDns(runtime);
	return runtime;
}

async function call(runtime: PluginRuntimeTestHost, route: string, body: unknown, opts: { user?: typeof ADMIN; headers?: Record<string, string> } = {}) {
	const response = await runtime.actions.routes.request(route, {
		body,
		user: opts.user ?? ADMIN,
		headers: { "X-EmDash-Request": "1", "X-Real-IP": OWN, ...opts.headers },
	});
	return { status: response.status, data: ((await response.json()) as { data?: Record<string, unknown> }).data ?? {} };
}

const posts = (runtime: PluginRuntimeTestHost) => runtime.http.requests().filter((r) => r.method === "POST" && r.url === `${LAPI}/v1/alerts`);

describe("ban_ip", () => {
	it("adds the alert cscli would, after the allowlist check", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["900"], 201));

		const { data } = await call(host, TOOL_ROUTES.ban, { address: "203.0.113.50", duration: "7d", note: "scraping" });

		expect(data).toMatchObject({ done: true, value: "203.0.113.50", alertId: "900", clientAddressChecked: true });
		const check = host.http.requests().find((r) => r.url === `${LAPI}/v1/allowlists/check`)!;
		expect(check.method).toBe("POST");
		expect(JSON.parse(new TextDecoder().decode(check.body))).toEqual({ targets: ["203.0.113.50"] });
		const [post] = posts(host);
		const [alert] = JSON.parse(new TextDecoder().decode(post!.body)) as Array<Record<string, any>>;
		expect(alert).toMatchObject({
			kind: "manual",
			remediation: true,
			events_count: 1,
			events: [],
			leakspeed: "0",
			source: { scope: "Ip", value: "203.0.113.50", ip: "203.0.113.50" },
			decisions: [{ duration: "168h", scope: "Ip", value: "203.0.113.50", type: "ban", origin: "cscli" }],
		});
		expect(alert.scenario).toBe("manual 'ban' from 'emdash-crowdsec' by Ada Admin: scraping");
		expect(alert.start_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
		expectUserAgent(host);
	});

	const refusals: Array<[string, string, RegExp]> = [
		["the MCP client's own address", OWN, /address this MCP client connects from \(198\.51\.100\.7\)/],
		["a range around the MCP client's address", "198.51.0.0/16", /address this MCP client connects from/],
		["the MCP client's address written as IPv4-mapped IPv6", `::ffff:${OWN}`, /address this MCP client connects from/],
		["the MCP client's address inside a NAT64 address", "64:ff9b::c633:6407", /address this MCP client connects from/],
		["a range written with host bits", "203.0.113.50/24", /Write it as 203\.0\.113\.0\/24/],
		["the site's address", "198.51.100.10", /this site's address/],
		["the LAPI host's address", "198.51.100.20", /LAPI host's address/],
		["the Protected addresses setting", "192.0.2.9", /Protected addresses setting/],
		["a private address", "10.0.0.1", /private, loopback/],
		["Tailscale's CGNAT space", "100.100.100.100", /private, loopback/],
		["a range wider than /16", "203.0.0.0/8", /wider than \/16/],
		["an IPv6 range wider than /48", "2a00:1450::/32", /wider than \/48/],
		["text that is not an address", "203.0.113.50; DROP", /not an IPv4 or IPv6/],
	];
	for (const [name, address, sentence] of refusals) {
		it(`refuses ${name}, with the rule in one sentence, before asking LAPI anything`, async () => {
			host = await writeHost();
			const { data } = await call(host, TOOL_ROUTES.ban, { address, duration: "4h" });
			expect(data.done).toBe(false);
			expect(data.message).toMatch(sentence);
			expect(host.http.requests()).toEqual([]);
		});
	}

	it("refuses an address on a CrowdSec allowlist, since LAPI skips that check for an alert with decisions", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [{ allowlists: ["203.0.113.51 from office (uplink)"], target: "203.0.113.51" }] }));
		const { data } = await call(host, TOOL_ROUTES.ban, { address: "203.0.113.51", duration: "4h" });
		expect(data).toMatchObject({ done: false, message: "Refused: the address is on a CrowdSec allowlist (203.0.113.51 from office (uplink))." });
		expect(posts(host)).toEqual([]);
	});

	it("still bans when the caller's address is unknown, and says it could not check it", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["901"], 201));
		const response = await host.actions.routes.request(TOOL_ROUTES.ban, {
			body: { address: "203.0.113.52", duration: "1h" },
			user: ADMIN,
			headers: { "X-EmDash-Request": "1" },
		});
		const { data } = (await response.json()) as { data: Record<string, unknown> };
		expect(data).toMatchObject({ done: true, clientAddressChecked: false });
		expect(data.message).toMatch(/Could not check it against the address this MCP client connects from/);
	});

	it("looks up the site's and LAPI's addresses when the cache is cold, and asks to be tried again", async () => {
		host = await newHost("lapi", { allowChanges: true });
		for (const [name, a, aaaa] of [
			["www.example.test", "198.51.100.10", "2001:db8::10"],
			["lapi.example.test", "198.51.100.20", null],
		] as const) {
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=A`, json({ Answer: [{ type: 5, data: "alias." }, { type: 1, data: a }] }));
			await host.http.respond(`https://cloudflare-dns.com/dns-query?name=${name}&type=AAAA`, json({ Answer: aaaa ? [{ type: 28, data: aaaa }] : [] }));
		}

		const first = await call(host, TOOL_ROUTES.ban, { address: "2001:db8::10", duration: "4h" });
		expect(first.data.message).toMatch(/just looked up.*Try again/);
		expect(host.http.requests().every((r) => r.headers.accept === "application/dns-json")).toBe(true);

		const second = await call(host, TOOL_ROUTES.ban, { address: "2001:db8::10", duration: "4h" });
		expect(second.data.message).toMatch(/this site's address \(2001:db8::10\)/);
	});

	it("refuses every change while a Protected addresses entry cannot be read, and names it", async () => {
		host = await writeHost({ protectedAddresses: "198.51.100.99, home.example.net" });
		const { data } = await call(host, TOOL_ROUTES.ban, { address: "203.0.113.50", duration: "4h" });
		expect(data.message).toMatch(/home\.example\.net cannot be read\. Only IP addresses and CIDR ranges/);
		expect((await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.50" })).data.message).toMatch(/home\.example\.net/);
		expect(host.http.requests()).toEqual([]);
	});

	it("refuses a LAPI URL that is not HTTPS or carries credentials, and never repeats the credentials", async () => {
		host = await writeHost({ lapiUrl: "https://user:hunter2@lapi.example.test/crowdsec-lapi" });
		const { data } = await call(host, TOOL_ROUTES.ban, { address: "203.0.113.50", duration: "4h" });
		expect(data.message).toMatch(/user name or password in it/);
		expect(JSON.stringify(data)).not.toContain("hunter2");
		expect(host.http.requests()).toEqual([]);
	});

	it("refuses while Allow changes is off", async () => {
		host = await writeHost({ allowChanges: false });
		expect((await call(host, TOOL_ROUTES.ban, { address: "203.0.113.50", duration: "4h" })).data.message).toMatch(/Changes are off/);
		expect(host.http.requests()).toEqual([]);
	});

	it("is refused by the host for an editor: the write routes need plugins:manage", async () => {
		host = await writeHost();
		for (const route of [TOOL_ROUTES.ban, TOOL_ROUTES.removeBan, TOOL_ROUTES.deleteAlert]) {
			const { status } = await call(host, route, {}, { user: EDITOR });
			expect(status, route).toBe(403);
		}
		expect(host.http.requests()).toEqual([]);
	});
});

describe("remove_ban", () => {
	it("finds decisions by scope and value, never ip=, and deletes only the exact, active ones by id", async () => {
		host = await writeHost();
		await host.http.respond(
			`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`,
			json([
				{ id: 1, decisions: [{ id: 11, value: "203.0.113.14", duration: "2h", type: "ban" }, { id: 12, value: "203.0.113.15", duration: "2h", type: "ban" }] },
				{ id: 2, decisions: [{ id: 21, value: "203.0.113.14", duration: "-3m", type: "ban" }, { id: 22, value: "203.0.113.14", duration: "30m", type: "captcha" }] },
			]),
		);
		await host.http.respond(`${LAPI}/v1/decisions/11`, json({ nbDeleted: "1" }));
		await host.http.respond(`${LAPI}/v1/decisions/22`, json({ nbDeleted: "1" }));

		const { data } = await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.14" });

		expect(data).toMatchObject({ done: true, removed: 2, remaining: 0 });
		const deletes = host.http.requests().filter((r) => r.method === "DELETE").map((r) => r.url);
		expect(deletes).toEqual([`${LAPI}/v1/decisions/11`, `${LAPI}/v1/decisions/22`]);
		expect(host.http.requests().some((r) => /[?&]ip=/.test(r.url) || r.url.includes("/v1/decisions?"))).toBe(false);
	});

	it("searches an IPv4-mapped address in the IPv4 form LAPI stores", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`, json([{ id: 1, decisions: [{ id: 11, value: "203.0.113.14", duration: "1h", type: "ban" }] }]));
		await host.http.respond(`${LAPI}/v1/decisions/11`, json({ nbDeleted: "1" }));
		const { data } = await call(host, TOOL_ROUTES.removeBan, { address: "::ffff:203.0.113.14" });
		expect(data).toMatchObject({ done: true, removed: 1, value: "203.0.113.14" });
	});

	it("removes a few per call and says how many remain", async () => {
		host = await writeHost();
		const decisions = Array.from({ length: 9 }, (_, i) => ({ id: 100 + i, value: "203.0.113.14", duration: "1h", type: "ban" }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`, json([{ id: 1, decisions }]));
		for (const d of decisions) await host.http.respond(`${LAPI}/v1/decisions/${d.id}`, json({ nbDeleted: "1" }));
		const { data } = await call(host, TOOL_ROUTES.removeBan, { address: "203.0.113.14" });
		expect(data.removed).toBeGreaterThan(0);
		expect((data.removed as number) + (data.remaining as number)).toBe(9);
		expect(data.message).toMatch(/run it again/);
	});
});

describe("delete_alert", () => {
	const alert = (duration: string | null) => ({ ...sampleAlerts().find((a) => a.id === 625), decisions: duration ? [{ id: 5, type: "ban", duration, value: "203.0.113.14" }] : null });

	it("refuses when a decision's end cannot be read", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/alerts/625`, json(alert("in a while")));
		expect((await call(host, TOOL_ROUTES.deleteAlert, { id: 625 })).data.message).toMatch(/cannot read/);
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("refuses while a decision is active, or ended less than two minutes ago", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/alerts/625`, json(alert("1h")));
		expect((await call(host, TOOL_ROUTES.deleteAlert, { id: 625 })).data.message).toMatch(/still has an active decision/);
		await host.http.respond(`${LAPI}/v1/alerts/625`, json(alert("-1m30s")));
		expect((await call(host, TOOL_ROUTES.deleteAlert, { id: 625 })).data.message).toMatch(/less than two minutes ago/);
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	const logRow = { day: "2026-10-09", part: "chunk", updatedAt: "", alerts: [625, 626].map((i) => ({ i, t: Date.parse("2026-10-08T20:24:29.000Z"), k: "h", s: "x", a: "203.0.113.14", c: "", o: "", p: "/", d: 0, b: 0 })) };

	it("says so when LAPI no longer has the alert, and deletes nothing", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/alerts/626`, json({ message: "object not found" }, 404));
		const { data } = await call(host, TOOL_ROUTES.deleteAlert, { id: 626 });
		expect(data.message).toMatch(/not in CrowdSec any more/);
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("deletes one alert by id once its decisions are long gone, and takes it out of the alert log", async () => {
		host = await writeHost();
		await host.fixtures.plugin.storage("log", "2026-10-09|c625", logRow);
		await host.http.respond(`${LAPI}/v1/alerts/625`, json(alert("-5m")));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ nbDeleted: "1" }));
		const { data } = await call(host, TOOL_ROUTES.deleteAlert, { id: 625 });
		expect(data).toMatchObject({ done: true, message: "Deleted alert 625." });
		expect(host.http.requests().filter((r) => r.method === "DELETE").map((r) => r.url)).toEqual([`${LAPI}/v1/alerts/625`]);
		// 20:24 UTC on 8 October is 9 October in Sydney: that day's row loses the alert and keeps the other.
		const row = await host.inspect.storage.get<{ alerts: Array<{ i: number }> }>("log", "2026-10-09|c625");
		expect(row?.alerts.map((a) => a.i)).toEqual([626]);
	});
});

describe("the admin pages' writes", () => {
	const active = [{ ...sampleAlerts()[0], decisions: [{ id: 1200226, type: "ban", duration: "3h", value: "203.0.113.10", origin: "crowdsec", scenario: "crowdsecurity/appsec-bot-challenge-too-many-requests" }] }];
	const activeUrl = `${LAPI}/v1/alerts?has_active_decision=true&simulated=false&include_capi=false&limit=100`;

	it("hides every write control from an editor, and refuses an editor's write", async () => {
		host = await writeHost();
		await host.http.respond(activeUrl, json(active));
		const page = await host.admin.loadPage(DECISIONS_PATH, { user: EDITOR });
		const text = JSON.stringify(page.blocks);
		expect(text).not.toContain(DECISIONS_REMOVE);
		expect(text).not.toContain(BAN_REVIEW);

		await host.http.respond(activeUrl, json(active));
		const res = await host.admin.act(DECISIONS_PATH, `${DECISIONS_REMOVE}|asc`, { value: 1200226, user: EDITOR });
		expect(res.toast).toMatchObject({ type: "error", message: "Only an administrator can change CrowdSec." });
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("shows the protected set and a Remove button with a confirmation to an administrator", async () => {
		host = await writeHost();
		await host.http.respond(activeUrl, json(active));
		const page = await host.admin.loadPage(DECISIONS_PATH);
		const text = JSON.stringify(page.blocks);
		// Each row's button has an action id of its own.
		expect(text).toContain('"action_id":"cs:decisions:remove|asc|1200226"');
		expect(text).toContain('"confirm":{');
		expect(text).toContain("198.51.100.10"); // the site
		expect(text).toContain("198.51.100.20"); // the LAPI host
		expect(text).toContain("192.0.2.0/24"); // the setting
	});

	it("removes one decision by id from its row", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/decisions/1200226`, json({ nbDeleted: "1" }));
		await host.http.respond(activeUrl, json([]));
		const res = await host.admin.act(DECISIONS_PATH, `${DECISIONS_REMOVE}|asc`, { value: 1200226 });
		expect(res.toast).toMatchObject({ type: "success" });
		expect(host.http.requests().find((r) => r.method === "DELETE")?.url).toBe(`${LAPI}/v1/decisions/1200226`);
	});

	it("reviews a ban from the form, then bans from the confirmed button", async () => {
		host = await writeHost();
		await host.http.respond(activeUrl, json([]));
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.60&has_active_decision=true&simulated=true&limit=20`, json([]));
		const review = await host.admin.submit(DECISIONS_PATH, BAN_REVIEW, { value: "203.0.113.60", duration: "24h", type: "captcha", note: "" });
		const text = JSON.stringify(review.blocks);
		expect(text).toContain(`"action_id":"${BAN_CONFIRM}"`);
		// The admin helper sends no forwarding headers, so the own-address check could not run, and the confirmation says so.
		expect(text).toContain("Could not confirm this is not your own address");
		expect(posts(host)).toEqual([]);

		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["902"], 201));
		await host.http.respond(activeUrl, json([]));
		const done = await host.admin.act(DECISIONS_PATH, BAN_CONFIRM, { value: { value: "203.0.113.60", duration: "24h", type: "captcha", note: "" } });
		expect(done.toast).toMatchObject({ type: "success" });
		const [alert] = JSON.parse(new TextDecoder().decode(posts(host)[0]!.body)) as Array<Record<string, any>>;
		expect(alert.decisions[0]).toMatchObject({ type: "captcha", duration: "24h" });
	});

	it("runs the allowlist check at the review step, so the review never offers a ban LAPI would allowlist", async () => {
		host = await writeHost();
		await host.http.respond(activeUrl, json([]));
		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [{ allowlists: ["203.0.113.0/24 from office (uplink)"], target: "203.0.113.61" }] }));
		const review = await host.admin.submit(DECISIONS_PATH, BAN_REVIEW, { value: "203.0.113.61", duration: "4h", type: "ban", note: "" });
		expect(review.toast).toMatchObject({ type: "error" });
		expect(review.toast?.message).toMatch(/allowlist/);
		expect(JSON.stringify(review.blocks)).not.toContain(BAN_CONFIRM);
	});

	it("refuses a ban on the caller's own address from the admin route too", async () => {
		host = await writeHost();
		await host.http.respond(activeUrl, json([]));
		const response = await host.actions.routes.request("admin", {
			body: { type: "block_action", page: DECISIONS_PATH, action_id: BAN_CONFIRM, value: { value: OWN, duration: "4h", type: "ban" } },
			user: ADMIN,
			headers: { "X-EmDash-Request": "1", "X-Forwarded-For": `${OWN}, 203.0.113.1` },
		});
		const { data } = (await response.json()) as { data: { toast?: { message: string } } };
		expect(data.toast?.message).toBe(`Refused: it covers your own address (${OWN}).`);
		expect(posts(host)).toEqual([]);
	});

	it("refuses to delete an alert from the explorer while its decision is active", async () => {
		host = await writeHost();
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions: [{ id: 5, duration: "10m" }] }));
		const refused = await host.admin.act(ALERTS_PATH, xid("del", { ...VIEW, d: "203.0.113.14", al: 625 }));
		expect(refused.toast).toMatchObject({ type: "error" });
		expect(refused.toast?.message).toMatch(/still has an active decision/);
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("deletes an old alert from its detail in the explorer, and takes it out of the alert log", async () => {
		host = await writeHost();
		const day = "2026-10-09";
		const entry = (i: number) => ({ i, t: Date.parse("2026-10-08T20:24:29.000Z"), k: "h", s: "x", a: "203.0.113.14", c: "", o: "", p: "/", d: 0, b: 0 });
		// More rows for the day than one query reads: the alert is on a later page.
		for (let n = 0; n < 150; n++) await host.fixtures.plugin.storage("log", `${day}|c${1000 + n}`, { day, part: "chunk", updatedAt: "", alerts: [entry(1000 + n)] });
		await host.fixtures.plugin.storage("log", `${day}|c625`, { day, part: "chunk", updatedAt: "", alerts: [entry(625), entry(626)] });
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ ...sampleAlerts().find((a) => a.id === 625), decisions: [{ id: 5, type: "ban", duration: "-10m", value: "203.0.113.14" }] }));
		await host.http.respond(`${LAPI}/v1/alerts/625`, json({ nbDeleted: "1" }));
		const done = await host.admin.act(ALERTS_PATH, xid("del", { ...VIEW, d: "203.0.113.14", al: 625 }));
		expect(done.toast).toEqual({ type: "success", message: "Deleted alert 625." });
		expect(host.http.requests().filter((r) => r.method === "DELETE").map((r) => r.url)).toEqual([`${LAPI}/v1/alerts/625`]);
		const row = await host.inspect.storage.get<{ alerts: Array<{ i: number }> }>("log", `${day}|c625`);
		expect(row?.alerts.map((a) => a.i)).toEqual([626]);
		// The page after it is the address's alerts, not the deleted alert's detail.
		expect(JSON.stringify(done.blocks)).not.toContain("cs:x:alfacts");
	});

	it("reviews and confirms a ban from an address's view in the explorer", async () => {
		host = await writeHost();
		const view = { ...VIEW, d: "203.0.113.60" };
		const page = await host.admin.act(ALERTS_PATH, xid("ipv", view));
		expect(JSON.stringify(page.blocks)).toContain(xid("banreview", view));

		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.60&has_active_decision=true&simulated=true&limit=20`, json([]));
		const review = await host.admin.submit(ALERTS_PATH, xid("banreview", view), { duration: "24h", type: "ban", note: "" });
		expect(review.toast).toBeUndefined();
		expect(JSON.stringify(review.blocks)).toContain(xid("banok", view));
		expect(posts(host)).toEqual([]);

		await host.http.respond(`${LAPI}/v1/allowlists/check`, json({ results: [] }));
		await host.http.respond(`${LAPI}/v1/alerts`, json(["905"], 201));
		const done = await host.admin.act(ALERTS_PATH, xid("banok", view), { value: { value: "203.0.113.60", duration: "24h", type: "ban", note: "" } });
		expect(done.toast).toMatchObject({ type: "success" });
		const [alert] = JSON.parse(new TextDecoder().decode(posts(host)[0]!.body)) as Array<Record<string, any>>;
		expect(alert.decisions[0]).toMatchObject({ type: "ban", duration: "24h", value: "203.0.113.60" });
	});

	it("refuses the explorer's ban of the caller's own address, and shows editors no write control", async () => {
		host = await writeHost();
		const view = { ...VIEW, d: OWN };
		const response = await host.actions.routes.request("admin", {
			body: { type: "block_action", page: ALERTS_PATH, action_id: xid("banok", view), value: { value: OWN, duration: "4h", type: "ban" } },
			user: ADMIN,
			headers: { "X-EmDash-Request": "1", "X-Forwarded-For": `${OWN}, 203.0.113.1` },
		});
		const { data } = (await response.json()) as { data: { toast?: { message: string } } };
		expect(data.toast?.message).toBe(`Refused: it covers your own address (${OWN}).`);
		expect(posts(host)).toEqual([]);

		const editor = await host.admin.act(ALERTS_PATH, xid("ipv", { ...VIEW, d: "203.0.113.60" }), { user: EDITOR });
		expect(JSON.stringify(editor.blocks)).not.toContain("banreview");
		const refused = await host.admin.act(ALERTS_PATH, xid("unban", { ...VIEW, d: "203.0.113.60" }), { user: EDITOR });
		expect(refused.toast).toMatchObject({ type: "error", message: "Only an administrator can change CrowdSec." });
		expect(host.http.requests().some((r) => r.method === "DELETE")).toBe(false);
	});

	it("removes the bans on an address from the explorer, by id", async () => {
		host = await writeHost();
		const view = { ...VIEW, d: "203.0.113.14" };
		await host.http.respond(`${LAPI}/v1/alerts?scope=Ip&value=203.0.113.14&has_active_decision=true&simulated=true&limit=50`, json([{ id: 1, decisions: [{ id: 11, value: "203.0.113.14", duration: "1h", type: "ban" }] }]));
		await host.http.respond(`${LAPI}/v1/decisions/11`, json({ nbDeleted: "1" }));
		const done = await host.admin.act(ALERTS_PATH, xid("unban", view));
		expect(done.toast).toMatchObject({ type: "success" });
		expect(host.http.requests().filter((r) => r.method === "DELETE").map((r) => r.url)).toEqual([`${LAPI}/v1/decisions/11`]);
	});
});
