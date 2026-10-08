import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import { checkBanTarget, parseNetwork, type ProtectedEntry } from "../src/net/ip.js";
import { withoutPort, callerAddresses } from "../src/net/protect.js";
import { settingsFrom } from "../src/settings.js";
import { compactSeen, countInto, emptyDay, MAX_SEEN_RANGES, type AlertRow } from "../src/store/rows.js";
import { DEFAULT_BATCH, MAX_BATCH, runSync, type SyncState } from "../src/sync/scheduler.js";
import { checkBan } from "../src/write/actions.js";
import { fakeCtx, json } from "./fake-ctx.js";
import { LAPI, newHost, sampleAlerts, setState, tick, ZONE } from "./host.js";

/**
 * The second review's findings, each with a test that fails without its fix.
 */

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

const DATASET = `lapi|${LAPI}|false|${ZONE}`;

describe("settings that cannot be used never wipe the stored history", () => {
	async function withHistory() {
		const runtime = await newHost("lapi");
		await runtime.fixtures.plugin.storage("alerts", "1", { id: 1, startedAt: "2026-10-01T00:00:00.000Z" });
		await runtime.fixtures.plugin.storage("days", "2026-10-01", { date: "2026-10-01", alerts: 1 });
		await setState(runtime, { dataset: DATASET, head: new Date().toISOString(), gaps: [], lastSync: "x" });
		return runtime;
	}

	it("a refused LAPI URL pauses the sync and keeps every row", async () => {
		host = await withHistory();
		await host.fixtures.plugin.setting("lapiUrl", "http://lapi.example.test/crowdsec-lapi");
		for (let i = 0; i < 3; i++) await tick(host)();
		await expect(host.inspect.storage.list("alerts")).resolves.toHaveLength(1);
		await expect(host.inspect.storage.list("days")).resolves.toHaveLength(1);
		const state = await host.inspect.kv.get<SyncState>("sync.state");
		expect(state).toMatchObject({ dataset: DATASET, lastProblem: { key: "urlNotHttps" } });
		expect(host.http.requests()).toEqual([]);
	});

	it("an unknown time zone pauses the sync and keeps every row, rather than counting days in the default zone", async () => {
		// History counted in Berlin: a silent fallback to Sydney would read as a new dataset.
		host = await withHistory();
		const berlin = `lapi|${LAPI}|false|Europe/Berlin`;
		await setState(host, { dataset: berlin, head: new Date().toISOString(), gaps: [], lastSync: "x" });
		await host.fixtures.plugin.setting("timeZone", "Europe/Berlinn");
		for (let i = 0; i < 3; i++) await tick(host)();
		await expect(host.inspect.storage.list("alerts")).resolves.toHaveLength(1);
		const state = await host.inspect.kv.get<SyncState>("sync.state");
		expect(state).toMatchObject({ dataset: berlin, lastProblem: { key: "timeZoneInvalid", params: { zone: "Europe/Berlinn" } } });
	});

	it("a cleared password pauses the sync too", async () => {
		host = await withHistory();
		await host.fixtures.plugin.setting("machinePassword", "");
		await tick(host)();
		await expect(host.inspect.storage.list("alerts")).resolves.toHaveLength(1);
	});

	it("reads an unknown zone as a problem and an unset one as the default", () => {
		const bad = settingsFrom(new Map<string, unknown>([["source", "demo"], ["timeZone", "Mars/Olympus"]]));
		expect(bad.ok ? null : bad.problem.key).toBe("timeZoneInvalid");
		expect(settingsFrom(new Map<string, unknown>([["source", "demo"]]))).toMatchObject({ ok: true, settings: { timeZone: "Australia/Sydney" } });
	});
});

describe("the lease", () => {
	it("discards the state write of a tick that overran while another claimed the state", async () => {
		let other = false;
		const fake = fakeCtx({
			settings: { source: "demo", timeZone: ZONE },
			onPut: (name) => {
				// Another tick claims the state while this one is writing rows.
				if (name === "alerts" && !other) {
					other = true;
					fake.setState({ dataset: "theirs", lastSync: "theirs" });
				}
			},
		});
		await runSync(fake.ctx, new Date(), "scheduled");
		expect(other).toBe(true);
		expect(fake.state()).toEqual({ dataset: "theirs", lastSync: "theirs" });
	});

	it("schedules a Refresh or a ban count again a minute later when the lease is taken", async () => {
		const fake = fakeCtx({ settings: { source: "demo", timeZone: ZONE } });
		const now = new Date("2026-10-09T00:00:00Z");
		fake.setState({ lease: { owner: "other", until: new Date(now.getTime() + 60_000).toISOString() } });
		await runSync(fake.ctx, now, "refresh");
		await runSync(fake.ctx, now, "bans");
		await runSync(fake.ctx, now, "scheduled");
		expect(fake.scheduled).toEqual([
			{ name: "refresh", schedule: "2026-10-09T00:01:00.000Z" },
			{ name: "bans", schedule: "2026-10-09T00:01:00.000Z" },
		]);
	});
});

describe("a burst of alerts in one second", () => {
	it("grows the batch first, and steps the gap back a second when the bigger batch is too large", async () => {
		const now = new Date();
		const to = new Date(now.getTime() - 3_600_000);
		to.setUTCMilliseconds(0);
		const burst = Array.from({ length: DEFAULT_BATCH }, (_, i) => ({ ...sampleAlerts()[1], id: 70_000 + i, start_at: to.toISOString(), created_at: to.toISOString() }));
		let searches = 0;
		const fake = fakeCtx({
			settings: { source: "lapi", lapiUrl: LAPI, machineId: "m", machinePassword: "p", timeZone: ZONE },
			fetch: async (url) => {
				if (url.endsWith("/v1/watchers/login")) return json({ token: "t" });
				searches++;
				if (searches === 1) return json(burst);
				throw new Error("Plugin HTTP response body exceeds the 8388608 byte limit");
			},
		});
		const gap = { from: new Date(now.getTime() - 5 * 86_400_000).toISOString(), to: to.toISOString() };
		fake.setState({ dataset: DATASET, head: now.toISOString(), gaps: [gap], slot: 1, lastSync: "x" });

		await runSync(fake.ctx, now, "catchup", "catchup-a");
		expect(fake.state()).toMatchObject({ batch: DEFAULT_BATCH * 2, burst: gap.to, gaps: [gap] });
		expect(DEFAULT_BATCH * 2).toBeLessThanOrEqual(MAX_BATCH);

		await runSync(fake.ctx, now, "catchup", "catchup-b");
		const after = fake.state()!;
		expect(after.lastProblem.key).toBe("tooLarge");
		expect(after.gaps[0].to).toBe(new Date(to.getTime() - 1000).toISOString());
		expect(after.burst).toBeUndefined();
	});
});

describe("the ban protections' lookup", () => {
	const lapiSettings = { source: "lapi", lapiUrl: LAPI, machineId: "m", machinePassword: "p", timeZone: ZONE, allowChanges: true };
	const active = (url: string) => {
		if (url.endsWith("/v1/watchers/login")) return json({ token: "t" });
		if (url.includes("has_active_decision=true")) return json(sampleAlerts());
		throw new Error(`unexpected ${url}`);
	};

	it("still counts the bans when the lookup fails, and waits six hours before looking again", async () => {
		const fake = fakeCtx({
			settings: lapiSettings,
			fetch: async (url) => (url.startsWith("https://cloudflare-dns.com") ? json({}, 500) : active(url)),
		});
		const now = new Date();
		fake.setState({ dataset: DATASET, head: now.toISOString(), gaps: [], slot: 2, lastSync: "x" });
		await runSync(fake.ctx, now, "scheduled");
		const state = fake.state()!;
		expect(state.active?.bans).toBeGreaterThan(0);
		expect(Date.parse(state.dnsRetryAt) - now.getTime()).toBe(6 * 3_600_000);

		fake.requests.length = 0;
		fake.setState({ ...state, slot: 2 });
		await runSync(fake.ctx, now, "scheduled");
		expect(fake.requests.some((u) => u.includes("cloudflare-dns"))).toBe(false);
	});

	it("never tries to look up a local site name, and refuses bans while the site has one", async () => {
		const fake = fakeCtx({
			settings: lapiSettings,
			siteUrl: "http://localhost:4321",
			fetch: async (url) => (url.startsWith("https://cloudflare-dns.com") ? json({ Answer: [{ type: 1, data: "198.51.100.20" }] }) : active(url)),
		});
		const now = new Date();
		fake.setState({ dataset: DATASET, head: now.toISOString(), gaps: [], slot: 2, lastSync: "x" });
		await runSync(fake.ctx, now, "scheduled");
		expect(fake.requests.some((u) => u.includes("name=localhost"))).toBe(false);
		expect(fake.state()?.active?.bans).toBeGreaterThan(0);

		const result = settingsFrom(new Map(Object.entries(lapiSettings)));
		const checked = await checkBan(fake.ctx, result.ok ? result.settings : result.partial, null, {}, "203.0.113.9", now);
		expect(checked.ok ? null : checked.problem).toEqual({ key: "localSiteName", params: { name: "localhost" } });
	});
});

describe("addresses", () => {
	it("drops the port and brackets a forwarding header may carry", () => {
		expect(withoutPort("203.0.113.5:4711")).toBe("203.0.113.5");
		expect(withoutPort("[2001:db8::1]:443")).toBe("2001:db8::1");
		expect(withoutPort("[2001:db8::1]")).toBe("2001:db8::1");
		expect(withoutPort("2001:db8::1")).toBe("2001:db8::1");
		expect(callerAddresses({ request: { headers: { "x-forwarded-for": "203.0.113.5:4711, [2001:db8::1]:443" } } }).sort()).toEqual(["2001:db8::1", "203.0.113.5"]);
	});

	it("judges SIIT addresses by the IPv4 address they carry, and refuses local-use NAT64 and Teredo", () => {
		const own: ProtectedEntry[] = [{ network: parseNetwork("198.51.100.7")!, rule: "caller" }];
		expect(checkBanTarget("::ffff:0:c633:6407", own)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("::ffff:0:a00:1", [])).toMatchObject({ ok: false, reason: "reservedAddress" }); // 10.0.0.1
		expect(checkBanTarget("64:ff9b:1:c633:6407::1", [])).toMatchObject({ ok: false, reason: "reservedAddress" });
		expect(checkBanTarget("2001:0:4136:e378:8000:63bf:3fff:fdd2", [])).toMatchObject({ ok: false, reason: "reservedAddress" });
		// Documentation space next door is not Teredo.
		expect(checkBanTarget("2001:db8::7", [])).toMatchObject({ ok: true });
	});
});

describe("the ids a day row keeps", () => {
	const row = (id: number, day: string): AlertRow =>
		({ id, day, kind: "waf", scenario: "s", ip: "", country: "", asName: "", path: "", decisions: 0, bans: 0 }) as unknown as AlertRow;

	it("keeps only alerts that started on the row's own day", () => {
		const day = emptyDay("2026-10-09", new Date());
		expect(countInto(day, row(5, "2026-10-08"))).toBe(false);
		expect(day.seen).toEqual([]);
	});

	it("stays within a fixed number of ranges, joining the closest", () => {
		const day = emptyDay("2026-10-09", new Date());
		for (let i = 0; i < MAX_SEEN_RANGES * 3; i++) countInto(day, row(i * 10 + (i % 7 === 0 ? 3 : 0), "2026-10-09"));
		expect(day.seen.length).toBeLessThanOrEqual(MAX_SEEN_RANGES);
		expect(day.alerts).toBe(MAX_SEEN_RANGES * 3);
		expect(compactSeen([[1, 1], [3, 3], [10, 10]], 2)).toEqual([[1, 3], [10, 10]]);
	});
});
