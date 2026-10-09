import { describe, expect, it } from "vitest";

import { alertSearch, LapiClient, normalizeBaseUrl } from "../src/lapi/client.js";
import { USER_AGENT } from "../src/version.js";

const BASE = "https://lapi.example.test/crowdsec-lapi";
const NOW = new Date("2026-10-09T00:00:00.000Z");

interface Seen {
	url: string;
	method: string;
	redirect?: string;
	headers: Record<string, string>;
	body?: string;
}

/** A LAPI that answers from a list of handlers, in order, and records what it was asked. */
function fakeLapi(handlers: Array<(req: Seen) => Response | Promise<Response>>) {
	const seen: Seen[] = [];
	const fetch = async (url: string, init?: RequestInit) => {
		const req: Seen = {
			url,
			method: init?.method ?? "GET",
			...(init?.redirect && { redirect: init.redirect }),
			headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])),
			...(typeof init?.body === "string" && { body: init.body }),
		};
		seen.push(req);
		const handler = handlers.shift();
		if (!handler) throw new Error(`unexpected request ${url}`);
		return handler(req);
	};
	return { seen, fetch };
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
const login = () => json({ code: 200, expire: "2026-10-09T01:00:00Z", token: "tok" });

function client(lapi: ReturnType<typeof fakeLapi>) {
	return new LapiClient({ baseUrl: BASE, machineId: "emdash-crowdsec", password: "pw", fetch: lapi.fetch, now: () => NOW });
}

describe("the alert search", () => {
	it("writes since as a duration back from now, widened by a minute, and until exactly, in a fixed order", () => {
		const since = new Date(NOW.getTime() - 24 * 3_600_000);
		const until = new Date(NOW.getTime() - 3_600_000);
		expect(alertSearch({ since, until, limit: 200 }, NOW)).toBe("since=86460s&until=3600s&simulated=false&include_capi=false&limit=200");
		expect(alertSearch({ activeOnly: true, limit: 100, simulated: true }, NOW)).toBe("has_active_decision=true&simulated=true&include_capi=false&limit=100");
		expect(alertSearch({ scope: "Ip", value: "2001:db8::1", limit: 50 }, NOW)).toBe("scope=Ip&value=2001%3Adb8%3A%3A1&simulated=false&include_capi=false&limit=50");
	});

	it("never searches with ip=", () => {
		expect(alertSearch({ scope: "Ip", value: "203.0.113.7", limit: 50 }, NOW)).not.toMatch(/(^|&)ip=/);
	});

	it("takes the LAPI URL with or without /v1 and trailing slashes", () => {
		expect(normalizeBaseUrl(" https://x.test/lapi/v1/ ")).toBe("https://x.test/lapi");
	});
});

describe("the client", () => {
	it("logs in as cscli does, with a name/version User-Agent, and keeps the token in memory only", async () => {
		const lapi = fakeLapi([login, () => json([]), () => json([])]);
		const c = client(lapi);
		expect(await c.alerts({ limit: 1 })).toEqual({ ok: true, value: [] });
		await c.alerts({ limit: 1 });
		expect(lapi.seen.map((r) => r.url.replace(BASE, ""))).toEqual(["/v1/watchers/login", "/v1/alerts?simulated=false&include_capi=false&limit=1", "/v1/alerts?simulated=false&include_capi=false&limit=1"]);
		expect(JSON.parse(lapi.seen[0]!.body!)).toEqual({ machine_id: "emdash-crowdsec", password: "pw", scenarios: [] });
		for (const req of lapi.seen) expect(req.headers["user-agent"]).toBe(USER_AGENT);
		expect(USER_AGENT).toMatch(/^emdash-crowdsec\/\d+\.\d+\.\d+$/);
		expect(lapi.seen[1]!.headers.authorization).toBe("Bearer tok");
		expect(c.calls).toBe(3);
	});

	it("follows no redirect, so the password never goes to another host", async () => {
		const lapi = fakeLapi([() => new Response(null, { status: 307, headers: { Location: "https://elsewhere.test/v1/watchers/login" } })]);
		const res = await client(lapi).login();
		expect(lapi.seen[0]!.redirect).toBe("manual");
		expect(res.ok ? null : res.problem).toEqual({ key: "redirected", params: { status: 307 } });
		expect(lapi.seen).toHaveLength(1);
	});

	it("measures LAPI's clock from the Date header and searches on it", async () => {
		const ahead = new Date(NOW.getTime() + 90_000).toUTCString();
		const lapi = fakeLapi([() => json({ token: "tok" }, 200, { Date: ahead }), () => json([])]);
		const c = client(lapi);
		await c.alerts({ until: new Date(NOW.getTime() - 3_600_000), limit: 5 });
		expect(c.skewMs).toBe(90_000);
		// LAPI's now is 90 s later, so the upper bound is 90 s further back from it.
		expect(lapi.seen[1]!.url).toBe(`${BASE}/v1/alerts?until=3690s&simulated=false&include_capi=false&limit=5`);
	});

	it("names each failure in a sentence", async () => {
		const cases: Array<[() => Response | Promise<Response>, string]> = [
			[() => json({ message: "incorrect Username or Password" }, 401), "m71"],
			[() => new Response("<html>403</html>", { status: 403 }), "m73"],
			[() => new Response("<html>sign in</html>", { status: 200 }), "m76"],
			[() => Promise.reject(new Error("Plugin HTTP response body exceeds the 8388608 byte limit")), "m7c"],
			[() => Promise.reject(new Error("connect ECONNREFUSED")), "unreachable"],
		];
		for (const [handler, key] of cases) {
			const res = await client(fakeLapi([handler])).alerts({ limit: 1 });
			expect(res.ok ? null : res.problem.key, key).toBe(key);
		}
		const refused = await client(fakeLapi([login, () => json({ message: "expired" }, 401)])).alerts({ limit: 1 });
		expect(refused.ok ? null : refused.problem.key).toBe("m72");
	});
});

describe("the allowlist check", () => {
	it("posts the target, as a range too, and reads an empty answer as not allowlisted", async () => {
		const lapi = fakeLapi([login, () => json({ results: [] })]);
		expect(await client(lapi).allowlisted("192.0.2.0/24")).toEqual({ ok: true, value: { allowlisted: false } });
		expect(lapi.seen[1]).toMatchObject({ url: `${BASE}/v1/allowlists/check`, method: "POST" });
		expect(JSON.parse(lapi.seen[1]!.body!)).toEqual({ targets: ["192.0.2.0/24"] });
	});

	it("counts a target with a non-empty allowlists list as allowlisted", async () => {
		const answer = {
			results: [{ allowlists: ["192.0.2.77 from plugin-test (test)"], target: "192.0.2.0/24" }],
		};
		const res = await client(fakeLapi([login, () => json(answer)])).allowlisted("192.0.2.0/24");
		expect(res).toEqual({ ok: true, value: { allowlisted: true, reason: "192.0.2.77 from plugin-test (test)" } });
	});

	it("fails closed on any other shape", async () => {
		for (const body of [{}, { allowlisted: false }, { results: [{ target: "x" }] }, { results: [{ allowlists: [1] }] }, null]) {
			const res = await client(fakeLapi([login, () => json(body)])).allowlisted("203.0.113.7");
			expect(res.ok ? null : res.problem.key, JSON.stringify(body)).toBe("m7d");
		}
	});
});

describe("deletes", () => {
	it("deletes one decision by id and never with a filter", async () => {
		const lapi = fakeLapi([login, () => json({ nbDeleted: "1" })]);
		expect(await client(lapi).deleteDecision(1185224)).toEqual({ ok: true, value: 1 });
		expect(lapi.seen[1]).toMatchObject({ url: `${BASE}/v1/decisions/1185224`, method: "DELETE" });
	});
});
