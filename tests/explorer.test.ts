import { describe, expect, it } from "vitest";

import { behaviourOf } from "../src/explorer/behaviour.js";
import {
	breakdown,
	bucketsOf,
	decodeView,
	DEFAULT_VIEW,
	encodeView,
	groupByIp,
	MAX_DAY_BARS,
	percents,
	rangeOf,
	select,
	withFilter,
	withView,
	type ExplorerView,
} from "../src/explorer/model.js";
import { chunksOf, flatten, PART_SIZE, partsOf, type LogAlert } from "../src/store/log.js";
import { compactAlert, countInto, emptyDay } from "../src/store/rows.js";
import { parseEngineNames } from "../src/settings.js";
import { dayStart } from "../src/sync/time.js";
import { engineLabel, formatCompact } from "../src/ui/format.js";
import { sampleAlerts } from "./host.js";

const SYDNEY = "Australia/Sydney";
const VIEW: ExplorerView = { ...DEFAULT_VIEW, f: {} };
const HOUR = 3_600_000;

function alert(i: number, t: number, over: Partial<LogAlert> = {}): LogAlert {
	return { i, t, k: "h", s: "crowdsecurity/http-probing", a: "203.0.113.1", c: "NL", o: "Example", p: "/", d: 1, b: 1, ...over };
}

describe("behaviours", () => {
	it("reads the behaviour from the scenario name, with Generic as the fallback", () => {
		expect(behaviourOf("crowdsecurity/vpatch-env-access")).toBe("http-exploit");
		expect(behaviourOf("crowdsecurity/CVE-2017-9841")).toBe("http-exploit");
		expect(behaviourOf("crowdsecurity/http-admin-interface-probing")).toBe("http-scan");
		expect(behaviourOf("crowdsecurity/http-sensitive-files")).toBe("http-scan");
		expect(behaviourOf("crowdsecurity/http-crawl-non_statics")).toBe("http-crawl");
		expect(behaviourOf("crowdsecurity/http-bad-user-agent")).toBe("http-crawl");
		expect(behaviourOf("crowdsecurity/appsec-bot-challenge-failed")).toBe("bot");
		expect(behaviourOf("crowdsecurity/ssh-bf")).toBe("ssh-bf");
		expect(behaviourOf("manual 'ban' from 'emdash'")).toBe("manual");
		expect(behaviourOf("someone/something-else")).toBe("generic");
	});
});

describe("the view in an action id", () => {
	it("survives the round trip, and anything it does not know falls back to the default", () => {
		const view: ExplorerView = { p: "7d", o: 2, k: "waf", f: { ip: "203.0.113.0/24", cn: "NL", sc: "a&b=c", bh: "http-scan" }, b: ["country", "path"], g: false, n: 3, d: "2001:db8::17", al: 42 };
		expect(decodeView(encodeView(view))).toEqual(view);
		expect(decodeView("p=forever&k=zzz&b=nope.nope&n=-4&o=99999&bh=hacking&ip=not-an-ip&d=x")).toEqual(VIEW);
	});

	it("goes back to the first page on any change but the page", () => {
		const paged = { ...VIEW, n: 4 };
		expect(withView(paged, { p: "3d" }).n).toBe(0);
		expect(withFilter(paged, "cn", "NL").n).toBe(0);
		expect(withView(paged, { n: 5 }).n).toBe(5);
		expect(withFilter(VIEW, "k", "bot").k).toBe("bot");
		expect(withFilter(VIEW, "k", "nonsense").k).toBeNull();
	});
});

describe("periods and histograms", () => {
	const now = new Date("2026-10-05T03:20:00.000Z"); // 2:20 pm on 5 October in Sydney, daylight time

	it("steps a rolling period back by its own length", () => {
		const r = rangeOf({ ...VIEW, p: "24h", o: 1 }, now, SYDNEY, 30, null);
		expect(r).toMatchObject({ until: now.getTime() - 24 * HOUR, since: now.getTime() - 48 * HOUR, bucket: "hour", steps: true });
	});

	it("counts 7 days as local days, today included, across the change to daylight time", () => {
		const r = rangeOf({ ...VIEW, p: "7d" }, now, SYDNEY, 30, null);
		expect(new Date(r.since).toISOString()).toBe("2026-09-28T14:00:00.000Z"); // midnight 29 September, standard time
		expect(r.until).toBe(now.getTime());
		const buckets = bucketsOf(r, SYDNEY);
		expect(buckets).toHaveLength(7);
		// 4 October has 23 hours.
		expect(buckets[5]!.end - buckets[5]!.start).toBe(23 * HOUR);
		expect(buckets[6]!.start).toBe(dayStart("2026-10-05", SYDNEY));
	});

	it("starts hourly buckets on the local hour in a zone half an hour off UTC", () => {
		const r = rangeOf({ ...VIEW, p: "24h" }, now, "Australia/Adelaide", 30, null);
		const buckets = bucketsOf(r, "Australia/Adelaide");
		expect(new Date(buckets[1]!.start).getUTCMinutes()).toBe(30);
		expect(buckets.every((b) => b.end - b.start === HOUR)).toBe(true);
	});

	it("reads Since last visit from the visit before, and caps a long period's bars", () => {
		const visit = new Date(now.getTime() - 5 * HOUR).toISOString();
		expect(rangeOf({ ...VIEW, p: "visit" }, now, SYDNEY, 30, visit)).toMatchObject({ since: Date.parse(visit), until: now.getTime(), bucket: "hour", steps: false });
		const year = rangeOf({ ...VIEW, p: "ret" }, now, SYDNEY, 400, null);
		expect(bucketsOf(year, SYDNEY).length).toBeLessThanOrEqual(MAX_DAY_BARS);
	});
});

describe("filters, breakdowns and groups", () => {
	const t0 = Date.parse("2026-10-05T00:00:00.000Z");
	const range = { since: t0, until: t0 + 3 * HOUR, bucket: "hour" as const, steps: true };
	const alerts = [
		alert(1, t0 + 10, { a: "203.0.113.5", k: "w", s: "crowdsecurity/vpatch-env-access", p: "/.env" }),
		alert(2, t0 + HOUR + 10, { a: "203.0.113.5", p: "/admin" }),
		alert(3, t0 + HOUR + 20, { a: "198.51.100.7", c: "US" }),
		alert(4, t0 + 2 * HOUR + 5, { a: "2001:db8::17", c: "DE", u: t0 + 10 * HOUR, y: "ban" }),
		alert(5, t0 + 2 * HOUR + 6, { a: "203.0.113.9", c: "FR" }),
		alert(6, t0 + 2 * HOUR + 7, { a: "203.0.113.10", c: "BR" }),
		alert(7, t0 - 5, { a: "203.0.113.5" }), // before the period
	];

	it("matches an address inside a range, and every other filter exactly", () => {
		expect(select(alerts, withFilter(VIEW, "ip", "203.0.113.0/24"), range).map((a) => a.i)).toEqual([1, 2, 5, 6]);
		expect(select(alerts, withFilter(VIEW, "ip", "2001:db8::/32"), range).map((a) => a.i)).toEqual([4]);
		expect(select(alerts, withFilter(VIEW, "bh", "http-exploit"), range).map((a) => a.i)).toEqual([1]);
		expect(select(alerts, withFilter(withFilter(VIEW, "cn", "NL"), "tg", "/admin"), range).map((a) => a.i)).toEqual([2]);
		expect(select(alerts, withFilter(VIEW, "k", "waf"), range).map((a) => a.i)).toEqual([1]);
	});

	it("shows the top three with their shares, the rest as Other, and stacks them by bucket", () => {
		const selected = select(alerts, VIEW, range);
		const b = breakdown(selected, "ip", bucketsOf(range, "UTC"));
		expect(b.total).toBe(6);
		expect(b.top[0]).toEqual({ value: "203.0.113.5", alerts: 2, share: 2 / 6 });
		expect(b.top).toHaveLength(3);
		expect(b.other).toBe(2);
		// Every alert lands in one bar, and the bars add up to the total.
		expect(b.series.flat().reduce((n, v) => n + v, 0)).toBe(6);
		expect(b.series[0]).toEqual([1, 1, 0]);
	});

	it("groups by source address, latest first, with the time span and a ban still running", () => {
		const groups = groupByIp(select(alerts, VIEW, range), new Date(t0 + 3 * HOUR));
		expect(groups.map((g) => g.ip)).toEqual(["203.0.113.10", "203.0.113.9", "2001:db8::17", "198.51.100.7", "203.0.113.5"]);
		const five = groups.find((g) => g.ip === "203.0.113.5")!;
		expect(five).toMatchObject({ alerts: 2, waf: 1, first: t0 + 10, last: t0 + HOUR + 10, decisions: 2 });
		expect(five.paths.map(([p]) => p).sort()).toEqual(["/.env", "/admin"]);
		expect(groups.find((g) => g.ip === "2001:db8::17")!.bannedUntil).toBe(t0 + 10 * HOUR);
	});
});

describe("review fixes", () => {
	it("keeps a paged rolling period on the end its first page had, so no address is dropped or repeated", () => {
		const first = new Date("2026-10-05T03:00:00.000Z");
		const later = new Date(first.getTime() + 10 * 60_000);
		const anchored = { ...VIEW, p: "24h" as const, at: first.getTime(), n: 1 };
		expect(rangeOf(anchored, later, SYDNEY, 30, null).until).toBe(first.getTime());
		expect(decodeView(encodeView(anchored)).at).toBe(first.getTime());
		// Any other change starts again from now.
		expect(withView(anchored, { p: "3d" }).at).toBeUndefined();
		expect(withView(anchored, { n: 2 }).at).toBe(first.getTime());

		// Thirty addresses, one alert each, paged ten at a time while a new alert arrives.
		const t0 = first.getTime() - HOUR;
		const alerts = Array.from({ length: 30 }, (_, i) => alert(i + 1, t0 + i * 60_000, { a: `203.0.113.${i + 1}` }));
		const seen: string[] = [];
		for (let n = 0; n < 3; n++) {
			const now = new Date(first.getTime() + n * 60_000);
			const all = n === 0 ? alerts : [...alerts, alert(99, now.getTime() - 1000, { a: "198.51.100.99" })];
			const view = { ...VIEW, n, ...(n > 0 && { at: first.getTime() }) };
			const range = rangeOf(view, now, SYDNEY, 30, null);
			seen.push(...groupByIp(select(all, view, range), now).slice(n * 10, n * 10 + 10).map((g) => g.ip));
		}
		expect(new Set(seen).size).toBe(30);
		expect(seen).toHaveLength(30);
	});

	it("matches an IPv4-mapped address with its IPv4 form both ways, and never a NAT64 form", () => {
		const t0 = Date.parse("2026-10-05T00:00:00.000Z");
		const range = { since: t0, until: t0 + HOUR, bucket: "hour" as const, steps: true };
		const alerts = [alert(1, t0 + 1, { a: "203.0.113.5" }), alert(2, t0 + 2, { a: "::ffff:198.51.100.7" }), alert(3, t0 + 3, { a: "64:ff9b::cb00:7105" })];
		expect(select(alerts, withFilter(VIEW, "ip", "::ffff:203.0.113.5"), range).map((a) => a.i)).toEqual([1]);
		expect(select(alerts, withFilter(VIEW, "ip", "198.51.100.0/24"), range).map((a) => a.i)).toEqual([2]);
		expect(select(alerts, withFilter(VIEW, "ip", "203.0.113.5"), range).map((a) => a.i)).toEqual([1]);
		expect(select(alerts, withFilter(VIEW, "ip", "203.0.113.0/24"), range).map((a) => a.i)).toEqual([1]);
	});

	it("keeps a filter as long as a stored value, 200 characters", () => {
		const path = `/${"a".repeat(199)}`;
		expect(decodeView(encodeView(withFilter(VIEW, "tg", path))).f.tg).toBe(path);
		expect(decodeView(encodeView(withFilter(VIEW, "tg", `${path}b`))).f.tg).toBeUndefined();
	});

	it("rounds shares so the top three and Other add up to 100", () => {
		expect(percents([1, 1, 1])).toEqual([34, 33, 33]);
		expect(percents([2, 1, 1, 3])).toEqual([29, 14, 14, 43]);
		expect(percents([0, 0])).toEqual([0, 0]);
		for (const counts of [[7, 5, 3, 1], [10, 10, 10, 1], [1, 2, 3, 4]]) expect(percents(counts).reduce((n, p) => n + p, 0)).toBe(100);
	});
});

describe("engines", () => {
	it("reads the Engine names setting, one per line or comma-separated, skipping entries it cannot read", () => {
		expect(parseEngineNames("edge-machine = Edge, web-machine = Web\napi-machine=API\nnonsense\n = nameless\nidless =")).toEqual({
			"edge-machine": "Edge",
			"web-machine": "Web",
			"api-machine": "API",
		});
		expect(parseEngineNames(undefined)).toEqual({});
	});

	it("names an engine from the setting, or shows its id, cut to 8 characters when it is a long generated one", () => {
		const id = "3f9e2c7a51d84b0e9c6a2f1d8b7e4c05AbCdEfGhIjKlMnOp";
		expect(engineLabel(id, {}, "en")).toBe("3f9e2c7a…");
		expect(engineLabel(id, { [id]: "API host" }, "en")).toBe("API host");
		expect(engineLabel("web-machine", {}, "en")).toBe("web-machine");
		expect(engineLabel("", {}, "en")).toBe("Unknown");
	});

	it("keeps the machine on the stored row and the log, counts it per day, and filters and groups by it", () => {
		const now = new Date();
		const row = compactAlert({ ...sampleAlerts()[0]!, machine_id: "edge-01" }, now, SYDNEY)!;
		expect(row.machine).toBe("edge-01");
		expect(chunksOf([row], now)[0]!.data.alerts[0]!.m).toBe("edge-01");
		const day = emptyDay(row.day, now);
		countInto(day, row);
		expect(day.machines).toEqual({ "edge-01": 1 });

		const t0 = Date.parse("2026-10-05T00:00:00.000Z");
		const range = { since: t0, until: t0 + HOUR, bucket: "hour" as const, steps: true };
		const alerts = [alert(1, t0 + 1, { m: "edge-01" }), alert(2, t0 + 2, { m: "web-02" }), alert(3, t0 + 3)];
		expect(select(alerts, withFilter(VIEW, "en", "web-02"), range).map((a) => a.i)).toEqual([2]);
		expect(groupByIp(alerts, new Date(t0 + HOUR))[0]!.engines.sort()).toEqual(["edge-01", "web-02"]);
		expect(breakdown(alerts, "engine", bucketsOf(range, "UTC")).top.map((t) => t.value)).toEqual(["", "edge-01", "web-02"]);
	});
});

describe("the alert log", () => {
	it("writes one chunk per local day and reads every alert once, even while a day is half merged", () => {
		const now = new Date();
		const rows = sampleAlerts()
			.map((raw) => compactAlert(raw, now, SYDNEY))
			.filter((row) => row !== null);
		const chunks = chunksOf(rows, now);
		expect(chunks.map((c) => c.data.day)).toEqual([...new Set(rows.map((r) => r.day))]);
		expect(chunks[0]!.id).toBe(`${chunks[0]!.data.day}|c${Math.min(...chunks[0]!.data.alerts.map((a) => a.i))}`);
		const merged = partsOf(chunks[0]!.data.day, chunks[0]!.data.alerts, now);
		expect(flatten([...merged.map((m) => m.data), ...chunks.map((c) => c.data)])).toHaveLength(rows.length);
	});

	it("splits a busy day into parts of at most PART_SIZE alerts, oldest first", () => {
		const many = Array.from({ length: PART_SIZE * 2 + 5 }, (_, i) => alert(i + 1, 1_000_000 - i));
		const parts = partsOf("2026-10-05", many, new Date());
		expect(parts.map((p) => p.id)).toEqual(["2026-10-05|p0", "2026-10-05|p1", "2026-10-05|p2"]);
		expect(parts.map((p) => p.data.alerts.length)).toEqual([PART_SIZE, PART_SIZE, 5]);
		expect(parts[0]!.data.alerts[0]!.t).toBeLessThan(parts[2]!.data.alerts[4]!.t);
	});
});

describe("compact times", () => {
	it("fits a table cell: no year in the current one, the year otherwise, 24-hour", () => {
		const now = new Date("2026-10-09T01:00:00.000Z");
		expect(formatCompact("2026-10-09T00:54:00.000Z", "en", SYDNEY, now)).toBe("9 Oct 11:54");
		expect(formatCompact("2025-12-31T20:05:00.000Z", "en", SYDNEY, now)).toBe("1 Jan 07:05");
		expect(formatCompact("2025-06-01T04:05:00.000Z", "en", SYDNEY, now)).toBe("1 June 2025 14:05");
	});
});
