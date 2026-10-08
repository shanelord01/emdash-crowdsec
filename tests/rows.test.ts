import { describe, expect, it } from "vitest";

import { compactAlert, countInto, emptyDay, kindOf, seenAdd, seenHas, trimDay, DAY_TOP_KEEP } from "../src/store/rows.js";
import { activeOf } from "../src/sync/scheduler.js";
import { sampleAlerts, ZONE } from "./host.js";

const READ_AT = new Date("2026-10-08T22:00:00Z");

describe("compacting LAPI alerts", () => {
	const rows = sampleAlerts().map((raw) => compactAlert(raw, READ_AT, ZONE)!);

	it("keeps a few hundred bytes of each ~13 KB alert", () => {
		for (const row of rows) expect(JSON.stringify(row).length).toBeLessThan(800);
	});

	it("sorts the real kinds into WAF, bot challenge and behaviour", () => {
		const byId = Object.fromEntries(rows.map((row) => [row.id, row.kind]));
		expect(byId[662]).toBe("waf"); // vpatch-CVE-2025-29927, kind waf
		expect(byId[667]).toBe("bot"); // appsec-bot-challenge-too-many-requests, kind crowdsec
		expect(byId[649]).toBe("behaviour"); // http-technology-probing
		expect(kindOf({ kind: "bot-detection", scenario: "x" })).toBe("bot");
		expect(kindOf({ kind: "manual", scenario: "manual 'ban' from 'emdash-crowdsec' by Ada" })).toBe("manual");
	});

	it("reads source, path and decision fields", () => {
		const banned = rows.find((row) => row.id === 625)!;
		expect(banned).toMatchObject({
			ip: "203.0.113.14",
			country: "NL",
			asName: "GOOGLE-CLOUD-PLATFORM",
			path: "/admin",
			decisions: 1,
			bans: 1,
			decisionType: "ban",
			// 2h22m2s after the read
			decisionUntil: new Date(READ_AT.getTime() + (2 * 3600 + 22 * 60 + 2) * 1000).toISOString(),
		});
		const waf = rows.find((row) => row.id === 662)!;
		expect(waf).toMatchObject({ path: "/configuration.js", decisions: 0, host: "www.example.com" });
		expect(waf.decisionUntil).toBeUndefined();
	});

	it("takes the first path of a JSON-encoded list and drops the query string", () => {
		expect(compactAlert({ id: 1, start_at: "2026-10-08T00:00:00Z", meta: [{ key: "target_uri", value: '["/a?x=1","/b"]' }] }, READ_AT, ZONE)?.path).toBe("/a");
	});

	it("skips an alert without an id or a time", () => {
		expect(compactAlert({ scenario: "x", start_at: "2026-10-08T00:00:00Z" }, READ_AT, ZONE)).toBeNull();
		expect(compactAlert({ id: 3 }, READ_AT, ZONE)).toBeNull();
	});
});

describe("counting into a day", () => {
	it("counts an alert once, whichever window brings it", () => {
		const day = emptyDay("2026-10-09", READ_AT);
		const [first, second] = sampleAlerts().map((raw) => compactAlert(raw, READ_AT, ZONE)!);
		expect(countInto(day, first!)).toBe(true);
		expect(countInto(day, second!)).toBe(true);
		expect(countInto(day, first!)).toBe(false);
		expect(day.alerts).toBe(2);
		expect(day.seen.length).toBeGreaterThan(0);
	});

	it("keeps counted ids as joined ranges", () => {
		let seen: Array<[number, number]> = [];
		for (const id of [5, 7, 6, 10, 1, 2]) seen = seenAdd(seen, id);
		expect(seen).toEqual([
			[1, 2],
			[5, 7],
			[10, 10],
		]);
		expect(seenHas(seen, 6)).toBe(true);
		expect(seenHas(seen, 8)).toBe(false);
	});

	it("keeps each day's top lists to the top 25", () => {
		const day = emptyDay("2026-10-09", READ_AT);
		for (let i = 0; i < 40; i++) day.scenarios[`s${i}`] = i;
		expect(Object.keys(trimDay(day).scenarios)).toHaveLength(DAY_TOP_KEEP);
		expect(trimDay(day).scenarios.s39).toBe(39);
		expect(trimDay(day).scenarios.s0).toBeUndefined();
	});
});

describe("active bans", () => {
	it("counts unexpired decisions and banned addresses, not expired ones", () => {
		const active = activeOf(
			[
				{ decisions: [{ type: "ban", duration: "1h", value: "203.0.113.1" }, { type: "captcha", duration: "5m", value: "203.0.113.2" }] },
				{ decisions: [{ type: "ban", duration: "-1m", value: "203.0.113.3" }, { type: "ban", duration: "30s", value: "203.0.113.1" }] },
				{ decisions: null },
			],
			READ_AT,
			false,
		);
		expect(active).toMatchObject({ bans: 1, decisions: 3, truncated: false });
	});
});
