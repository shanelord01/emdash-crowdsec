/**
 * Days, hours and Go durations. Pure. The zone work is `../time/zone.ts`,
 * shared word for word with emdash-to-buffer-plus so both plugins draw the
 * same day boundaries.
 *
 * Every day key, day boundary, range, retention cut-off and date label is
 * in one time zone: the Time zone setting (an IANA name, `Australia/Sydney`
 * unless changed), because EmDash does not tell a sandboxed plugin the
 * site's own. LAPI's times are UTC (`...Z`). A day keyed in UTC would put an
 * alert at 8:15 on a Sydney morning on the day before, and "today" would
 * roll over mid-morning. Days are worked out from `Intl.DateTimeFormat`
 * parts, never a fixed offset, so daylight saving moves with the zone.
 *
 * The rolling "last 24 hours" are plain hours and need no zone.
 */

export { addDays, daysBetween, DEFAULT_TIME_ZONE, type Day } from "../time/zone.js";
import { addDays, dayOf, dayStartMs, daysBetween, resolveTimeZone, type Day } from "../time/zone.js";

/** The zone if the runtime knows it, otherwise `Australia/Sydney`. */
export function validZone(raw: unknown): string {
	return resolveTimeZone(raw);
}

/** The local day an instant falls on. */
export function localDay(date: Date | number | string, zone: string): Day {
	return dayOf(date, zone);
}

/**
 * The first instant of a local day, in milliseconds. Usually local
 * midnight. Where the clocks skip midnight (America/Santiago on 6 September
 * 2026) it is when the day's clock starts.
 */
export function dayStart(day: Day, zone: string): number {
	return dayStartMs(day, zone);
}

export function enumerateDays(since: Day, until: Day): Day[] {
	const out: Day[] = [];
	for (let day = since; daysBetween(day, until) >= 0; day = addDays(day, 1)) out.push(day);
	return out;
}

/** A UTC hour, `YYYY-MM-DDTHH`, the key of the widget's hourly buckets. */
export function hourKey(date: Date | number): string {
	return new Date(date).toISOString().slice(0, 13);
}

export function hourStart(key: string): number {
	return Date.parse(`${key}:00:00.000Z`);
}

const UNIT_SECONDS: Record<string, number> = {
	ns: 1e-9,
	us: 1e-6,
	"µs": 1e-6,
	ms: 1e-3,
	s: 1,
	m: 60,
	h: 3600,
};

const DURATION_PART = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;

/**
 * A Go duration ("3h41m8.5s", "-1m30s", "300ms") in seconds, or null.
 *
 * LAPI reports a decision's remaining time this way, and the value goes
 * negative once the decision has expired.
 */
export function parseGoDuration(value: unknown): number | null {
	if (typeof value !== "string") return null;
	const text = value.trim();
	if (!text) return null;
	const negative = text.startsWith("-");
	const body = negative || text.startsWith("+") ? text.slice(1) : text;
	if (body === "0") return 0;
	let total = 0;
	let consumed = 0;
	for (const match of body.matchAll(DURATION_PART)) {
		total += Number(match[1]) * UNIT_SECONDS[match[2]!]!;
		consumed += match[0].length;
	}
	if (consumed === 0 || consumed !== body.length) return null;
	return negative ? -total : total;
}

/** Whole seconds as a Go duration LAPI accepts in `since` and `until`. */
export function secondsDuration(seconds: number): string {
	return `${Math.max(0, Math.ceil(seconds))}s`;
}

/** An ISO timestamp without milliseconds, as cscli sends them. */
export function rfc3339(date: Date): string {
	return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
