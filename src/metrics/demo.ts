/**
 * Traffic history for demo data. Pure.
 *
 * The demo metrics are counters that grow with time (`demoMetricsText`),
 * so what a day or an hour counted is the difference between the counters
 * at its end and at its start. Working that out at read time gives the
 * charts and the widget a full history from the first visit, with no
 * sampler run and nothing stored.
 */

import type { TrafficDay } from "../store/rows.js";
import { addDays, dayStart, hourKey, localDay, type Day } from "../sync/time.js";
import { parsePrometheus } from "./prom.js";
import { deltaOf, sampleOf, type Counters, type Gauges } from "./sample.js";
import { demoMetricsText } from "./sample.js";

const HOUR = 3_600_000;

function countersAt(ms: number): { counters: Counters; gauges: Gauges | null } {
	const at = new Date(ms);
	const sample = sampleOf(parsePrometheus(demoMetricsText("engine", at)), parsePrometheus(demoMetricsText("firewall", at)), at);
	return { counters: sample.counters, gauges: sample.gauges };
}

function between(from: number, to: number): Counters {
	return deltaOf(countersAt(from).counters, countersAt(to).counters);
}

/** One traffic day per local day from `since` to today, today up to `now`. */
export function demoTrafficDays(since: Day, zone: string, now: Date): TrafficDay[] {
	const today = localDay(now, zone);
	const out: TrafficDay[] = [];
	for (let day = since; day <= today && out.length < 400; day = addDays(day, 1)) {
		const start = dayStart(day, zone);
		const end = Math.min(now.getTime(), dayStart(addDays(day, 1), zone));
		out.push({ date: day, counters: between(start, end), samples: Math.round((end - start) / (15 * 60_000)), updatedAt: now.toISOString() });
	}
	return out;
}

/** What the sampler would keep after sampling demo data for `days` days: 48 hours by the hour, and the gauges. */
export function demoMetricsState(now: Date, days: number) {
	const hours: Record<string, Counters> = {};
	const top = Math.floor(now.getTime() / HOUR) * HOUR;
	for (let h = top - 48 * HOUR; h <= top; h += HOUR) hours[hourKey(h)] = between(h, Math.min(h + HOUR, now.getTime()));
	const current = countersAt(now.getTime());
	return {
		source: "demo",
		last: current.counters,
		at: now.toISOString(),
		hours,
		gauges: current.gauges,
		engine: { ok: true },
		firewall: { ok: true },
		since: new Date(now.getTime() - days * 24 * HOUR).toISOString(),
	};
}
