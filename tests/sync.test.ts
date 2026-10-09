import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { DayRow } from "../src/store/rows.js";
import type { LogRow } from "../src/store/log.js";
import { batchAfter, batchGrown, clipGaps, DEFAULT_BATCH, floorOf, runSync, MIN_BATCH, type SyncState } from "../src/sync/scheduler.js";
import { settingsFrom } from "../src/settings.js";
import { fakeCtx } from "./fake-ctx.js";
import { ENGINES, fakeLapi } from "./seed.js";
import { expectUserAgent, LAPI, newHost, respondLogin, respondSearch, sampleAlerts, setState, tick, ZONE } from "./host.js";

let host: PluginRuntimeTestHost | undefined;

afterEach(async () => {
	await host?.dispose();
	host = undefined;
	vi.unstubAllEnvs();
});

async function state(runtime: PluginRuntimeTestHost) {
	return (await runtime.inspect.kv.get<SyncState>("sync.state")) ?? {};
}

async function totals(runtime: PluginRuntimeTestHost) {
	const days = await runtime.inspect.storage.list<DayRow>("days");
	const log = await runtime.inspect.storage.list<LogRow>("log");
	const alerts = log.flatMap((row) => row.data.alerts);
	return { counted: days.reduce((n, d) => n + d.data.alerts, 0), rows: alerts.length, days, alerts, log };
}

describe("the sync over a LAPI with a few hundred alerts a day", () => {
	const lapi = { lapiUrl: LAPI, machineId: "m", machinePassword: "p", timeZone: ZONE };
	const totalsOf = (fake: ReturnType<typeof fakeCtx>) => {
		const days = [...fake.rows("days").values()] as DayRow[];
		const alerts = ([...fake.rows("log").values()] as LogRow[]).flatMap((row) => row.alerts);
		return { counted: days.reduce((n, d) => n + d.alerts, 0), rows: alerts.length, days, alerts };
	};

	it("reads the newest alerts first and leaves the rest of the retention as a gap", async () => {
		const now = new Date();
		const fake = fakeCtx({ settings: lapi, fetch: fakeLapi(() => now) });
		await runSync(fake.ctx, now, "scheduled");
		const s = fake.state()!;
		expect(s.lastProblem).toBeUndefined();
		expect(s.head).toEqual(expect.any(String));
		expect(s.gaps?.length).toBe(1);
		const { counted, rows } = totalsOf(fake);
		expect(rows).toBe(DEFAULT_BATCH);
		expect(counted).toBe(rows);
		expect(Object.keys(s.hours ?? {}).length).toBeGreaterThan(0);
	});

	it("counts each alert once across overlapping windows, and catches up to the retention limit", async () => {
		const now = new Date();
		const fake = fakeCtx({ settings: { ...lapi, retentionDays: 7 }, fetch: fakeLapi(() => now) });
		for (let i = 0; i < 30; i++) {
			await runSync(fake.ctx, now, i === 0 ? "scheduled" : "catchup", "catchup-a");
			if ((fake.state()?.gaps ?? []).length === 0) break;
		}
		expect(fake.state()?.gaps).toEqual([]);
		// Two forward steps over the same hour find nothing new to count.
		await runSync(fake.ctx, now, "refresh");
		await runSync(fake.ctx, now, "refresh");
		const { counted, rows, days, alerts } = totalsOf(fake);
		expect(counted).toBe(rows);
		expect(rows).toBeGreaterThan(DEFAULT_BATCH * 2);
		// Eight local days at most: today and the seven before.
		expect(days.length).toBeLessThanOrEqual(8);
		const ids = alerts.map((a) => a.i);
		expect(new Set(ids).size).toBe(ids.length);
		// Every engine that raised alerts is counted per day.
		expect(Object.keys(Object.assign({}, ...days.map((d) => d.machines ?? {}))).sort()).toEqual([...ENGINES].sort());
	});

	it("clears the store when the time zone changes, since days were counted in the old one", async () => {
		const now = new Date();
		const settings: Record<string, unknown> = { ...lapi };
		const fake = fakeCtx({ settings, fetch: fakeLapi(() => now) });
		await runSync(fake.ctx, now, "scheduled");
		expect(totalsOf(fake).rows).toBeGreaterThan(0);
		settings.timeZone = "Europe/Berlin";
		for (let i = 0; i < 10 && fake.state()?.dataset; i++) await runSync(fake.ctx, now, "scheduled");
		expect(totalsOf(fake).rows).toBe(0);
		expect(totalsOf(fake).days).toEqual([]);
	});
});

describe("an install that used demo data before 0.1.1", () => {
	it("pauses as not configured, then clears the demo rows once a LAPI is set", async () => {
		const now = new Date();
		const settings: Record<string, unknown> = { source: "demo", timeZone: ZONE };
		const fake = fakeCtx({ settings, fetch: fakeLapi(() => now) });
		const demoState = { dataset: `demo|false|${ZONE}`, head: now.toISOString(), gaps: [], lastSync: now.toISOString(), logMigrated: true };
		fake.setState(demoState);
		await fake.ctx.storage.log!.putMany([{ id: "2026-10-01|c1", data: { day: "2026-10-01", part: "chunk", alerts: [], updatedAt: "" } }]);

		// No LAPI yet: the sync pauses with "not configured", and keeps the rows.
		const paused = await runSync(fake.ctx, now, "scheduled");
		expect(paused).toMatchObject({ ok: false, problem: { key: "m6y" } });
		expect(fake.rows("log").size).toBe(1);
		expect(fake.state()?.dataset).toBe(demoState.dataset);

		// A LAPI is configured: the dataset changed, so the demo rows go first.
		Object.assign(settings, { lapiUrl: LAPI, machineId: "m", machinePassword: "p" });
		const wiped = await runSync(fake.ctx, now, "scheduled");
		expect(wiped.step).toBe("wipe");
		expect(fake.rows("log").size).toBe(0);
		await runSync(fake.ctx, now, "scheduled");
		expect(fake.state()?.dataset).toBe(`lapi|${LAPI}|false|${ZONE}`);
		expect(fake.rows("log").size).toBeGreaterThan(0);
	});
});

describe("the sync against a LAPI", () => {
	const settings = { retentionDays: 7, timeZone: ZONE };

	it("logs in, reads the newest window and stores compact rows by local day", async () => {
		host = await newHost("lapi", { retentionDays: 7 });
		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(floorOf(settings, now)), limit: DEFAULT_BATCH, simulated: false }), sampleAlerts());

		await tick(host)();

		const s = await state(host);
		expect(s.lastProblem).toBeUndefined();
		expect(s.gaps).toEqual([]); // fewer alerts than the batch: the window is complete
		const { alerts, days } = await totals(host);
		expect(alerts.map((a) => a.i).sort()).toEqual([573, 574, 576, 625, 646, 649, 662, 667]);
		// 2026-10-08T20:24Z and 21:43Z are 9 October in Sydney.
		expect(days.map((d) => d.data.date)).toEqual(["2026-10-09"]);
		expect(days[0]!.data).toMatchObject({ alerts: 8, waf: 2, bot: 1, behaviour: 5, bans: 5 });
		expectUserAgent(host);
		expect(host.http.requests().some((r) => /(\?|&)ip=/.test(r.url))).toBe(false);
	});

	it("logs in once per tick and stores no token, then reads the last 24 hours forward", async () => {
		host = await newHost("lapi", { retentionDays: 7 });
		await respondLogin(host, 200, 2);
		await respondSearch(host, (now) => ({ since: new Date(floorOf(settings, now)), limit: DEFAULT_BATCH, simulated: false }), []);
		await tick(host)();
		expect(await host.inspect.kv.list()).toEqual(expect.not.arrayContaining([expect.objectContaining({ key: "sync.session" })]));
		expect(JSON.stringify(await host.inspect.kv.list())).not.toContain("fresh-token");

		host.http.clear();
		await respondLogin(host);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 24 * 3_600_000), limit: DEFAULT_BATCH, simulated: false }), []);
		await tick(host, "refresh")();
		expect((await state(host)).lastProblem).toBeUndefined();
		expect(host.http.requests().map((r) => r.url.replace(LAPI, "").split("?")[0])).toEqual(["/v1/watchers/login", "/v1/alerts"]);
		expect(host.http.requests()[1]?.headers.authorization).toBe("Bearer fresh-token");
	});

	it("records a refused login as one sentence for the widget", async () => {
		host = await newHost("lapi");
		await respondLogin(host, 401);
		await tick(host)();
		expect((await state(host)).lastProblem?.key).toBe("m71");
	});

	it("turns a full forward batch into a gap only when even its oldest alert is newer than the previous head", async () => {
		host = await newHost("lapi", { retentionDays: 7 });
		const head = new Date(Date.now() - 6 * 3_600_000).toISOString();
		const base = sampleAlerts()[1]!;
		const batchOf = (createdAt: (i: number) => number) =>
			Array.from({ length: DEFAULT_BATCH }, (_, i) => ({ ...base, id: 10_000 + i, start_at: new Date(createdAt(i)).toISOString(), created_at: new Date(createdAt(i)).toISOString() }));

		// The oldest of a full batch was created after the head: alerts between were not reached.
		await setState(host, { dataset: `lapi|${LAPI}|false|${ZONE}`, head, gaps: [], slot: 0, lastSync: head });
		await respondLogin(host);
		const recent = batchOf((i) => Date.now() - 60_000 - i * 1000);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 24 * 3_600_000), limit: DEFAULT_BATCH, simulated: false }), recent);
		await tick(host)();
		const s1 = await state(host);
		expect(s1.lastProblem).toBeUndefined();
		expect(s1.gaps).toHaveLength(1);
		expect(s1.gaps![0]!.to).toBe(recent.at(-1)!.created_at);

		// A full batch reaching back past the head: everything new was read.
		await setState(host, { dataset: `lapi|${LAPI}|false|${ZONE}`, head, gaps: [], slot: 0, lastSync: head });
		host.http.clear();
		await respondLogin(host);
		const spanning = batchOf((i) => Date.now() - 60_000 - i * 3 * 60_000);
		await respondSearch(host, (now) => ({ since: new Date(now.getTime() - 24 * 3_600_000), limit: DEFAULT_BATCH, simulated: false }), spanning);
		await tick(host)();
		expect((await state(host)).gaps).toEqual([]);
	});

	it("skips a tick while another holds the lease", async () => {
		host = await newHost("lapi");
		await setState(host, { lease: { owner: "other", until: new Date(Date.now() + 60_000).toISOString() }, lastSync: "x" });
		await tick(host)();
		expect(host.http.requests()).toEqual([]);
		expect((await state(host)).lease?.owner).toBe("other");
	});
});

describe("window bookkeeping", () => {
	it("halves the batch after an answer over 8 MiB, down to a floor, and grows it back after steps that fit", () => {
		expect(batchAfter(200, "m7c")).toBe(100);
		expect(batchAfter(30, "m7c")).toBe(MIN_BATCH);
		expect(batchAfter(200, "unreachable")).toBe(200);
		expect(batchGrown(50)).toBe(100);
		expect(batchGrown(150)).toBe(DEFAULT_BATCH);
		expect(batchGrown(DEFAULT_BATCH)).toBe(DEFAULT_BATCH);
	});

	it("drops gaps behind the retention limit and opens one when the retention grows", () => {
		const now = new Date("2026-10-09T00:00:00Z");
		const result = settingsFrom(new Map<string, unknown>([["retentionDays", 30], ["timeZone", ZONE]]));
		const s = result.ok ? result.settings : result.partial;
		const oldFloor = floorOf({ retentionDays: 7, timeZone: ZONE }, now);
		const gaps = clipGaps(
			{ head: now.toISOString(), floor: oldFloor, gaps: [{ from: "2026-01-01T00:00:00Z", to: "2026-01-02T00:00:00Z" }] },
			s,
			now,
		);
		expect(gaps).toEqual([{ from: floorOf(s, now), to: oldFloor }]);
	});
});
