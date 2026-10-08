import { describe, expect, it } from "vitest";

import { compactAlert } from "../src/store/rows.js";
import { floorOf } from "../src/sync/scheduler.js";
import { addDays, dayStart, localDay, parseGoDuration, validZone } from "../src/sync/time.js";
import { formatTime } from "../src/ui/format.js";

const SYDNEY = "Australia/Sydney";

describe("local days", () => {
	it("puts an alert at 2026-09-26T22:15Z on 27 September in Sydney, not 26", () => {
		expect(localDay("2026-09-26T22:15:00Z", SYDNEY)).toBe("2026-09-27");
		expect(localDay("2026-09-26T22:15:00Z", "UTC")).toBe("2026-09-26");
	});

	it("keys LAPI's UTC created_at to the local day in a stored row", () => {
		const row = compactAlert(
			{ id: 1, scenario: "crowdsecurity/http-probing", kind: "crowdsec", start_at: "2026-09-26T22:15:00Z", created_at: "2026-09-26T22:15:04Z" },
			new Date("2026-09-27T00:00:00Z"),
			SYDNEY,
		);
		expect(row?.day).toBe("2026-09-27");
	});

	it("starts days at local midnight on both sides of the change to daylight time on 4 October 2026", () => {
		// AEST (+10) before, AEDT (+11) after 2:00 am on Sunday 4 October.
		expect(new Date(dayStart("2026-10-03", SYDNEY)).toISOString()).toBe("2026-10-02T14:00:00.000Z");
		expect(new Date(dayStart("2026-10-04", SYDNEY)).toISOString()).toBe("2026-10-03T14:00:00.000Z");
		expect(new Date(dayStart("2026-10-05", SYDNEY)).toISOString()).toBe("2026-10-04T13:00:00.000Z");
		// So 4 October has 23 hours.
		expect(dayStart("2026-10-05", SYDNEY) - dayStart("2026-10-04", SYDNEY)).toBe(23 * 3_600_000);
	});

	it("makes 5 April 2026, when daylight time ends, 25 hours long", () => {
		expect(new Date(dayStart("2026-04-05", SYDNEY)).toISOString()).toBe("2026-04-04T13:00:00.000Z");
		expect(dayStart("2026-04-06", SYDNEY) - dayStart("2026-04-05", SYDNEY)).toBe(25 * 3_600_000);
	});

	it("starts a day when its clock does where the change skips midnight", () => {
		// Chile: 6 September 2026 starts at 1 am, 2026-09-06T04:00Z.
		expect(new Date(dayStart("2026-09-06", "America/Santiago")).toISOString()).toBe("2026-09-06T04:00:00.000Z");
		expect(localDay("2026-09-06T03:59:59Z", "America/Santiago")).toBe("2026-09-05");
	});

	it("buckets a window across the change into the right local days", () => {
		const instants = [
			"2026-10-03T13:59:00Z", // 3 Oct, 11:59 pm AEST
			"2026-10-03T14:00:00Z", // 4 Oct, 00:00 AEST
			"2026-10-03T16:30:00Z", // 4 Oct, 3:30 am AEDT
			"2026-10-04T12:59:00Z", // 4 Oct, 11:59 pm AEDT
			"2026-10-04T13:00:00Z", // 5 Oct, 00:00 AEDT
		];
		expect(instants.map((at) => localDay(at, SYDNEY))).toEqual(["2026-10-03", "2026-10-04", "2026-10-04", "2026-10-04", "2026-10-05"]);
	});

	it("cuts retention at the start of a local day", () => {
		const floor = floorOf({ retentionDays: 2, timeZone: SYDNEY }, new Date("2026-10-05T01:00:00Z"));
		// 5 Oct, 12:00 pm AEDT, less two days, is the start of 3 Oct: 2 Oct 14:00 UTC.
		expect(floor).toBe("2026-10-02T14:00:00.000Z");
	});

	it("labels times in the zone", () => {
		expect(formatTime("2026-09-26T22:15:00Z", "en", SYDNEY)).toBe("27 Sept 2026, 8:15 am AEST");
		expect(formatTime("2026-10-04T00:00:00Z", "en", SYDNEY)).toBe("4 Oct 2026, 11:00 am AEDT");
	});

	it("falls back to Australia/Sydney for an unknown zone, and accepts a known one", () => {
		expect(validZone("Mars/Olympus")).toBe(SYDNEY);
		expect(validZone("")).toBe(SYDNEY);
		expect(validZone("Europe/Berlin")).toBe("Europe/Berlin");
	});

	it("does calendar arithmetic without a zone", () => {
		expect(addDays("2026-10-04", 1)).toBe("2026-10-05");
		expect(addDays("2026-03-01", -1)).toBe("2026-02-28");
	});
});

describe("Go durations", () => {
	it("reads LAPI's remaining time, negative once expired", () => {
		expect(parseGoDuration("3h41m8s")).toBe(13268);
		expect(parseGoDuration("-1m30s")).toBe(-90);
		expect(parseGoDuration("2h21m57.123456s")).toBeCloseTo(8517.123456);
		expect(parseGoDuration("300ms")).toBeCloseTo(0.3);
		expect(parseGoDuration("0")).toBe(0);
		expect(parseGoDuration("4 hours")).toBeNull();
		expect(parseGoDuration(undefined)).toBeNull();
	});
});
