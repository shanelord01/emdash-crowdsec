/**
 * The alert log: every stored alert, a few hundred bytes each, kept in
 * arrays rather than one row per alert. The Alerts explorer reads it.
 *
 * Grouping by address over a week reads every alert of the week. As rows of
 * their own, that is 1,600 rows for a site with 230 alerts a day, and
 * storage answers 100 a query, so a page could not load in ten bridge
 * calls. A per-address rollup could not apply alert-level filters, a
 * scenario or a path say, across addresses. So alerts are kept in chunks:
 *
 * - each sync step writes one chunk per local day it brought alerts for,
 *   with no read (`log:<day>|c<first id>`);
 * - the hourly maintenance run merges a closed day's chunks into one row,
 *   or several of `PART_SIZE` alerts on a very busy day (`log:<day>|p<n>`).
 *
 * Ninety days are then about 90 rows plus today's chunks: two or three
 * queries. Every panel, histogram, filter and group is worked out exactly,
 * in memory, from what the period holds.
 */

import type { AlertRow, Kind } from "./rows.js";

/** One alert, with short keys to keep a day's row small. */
export interface LogAlert {
	/** LAPI's alert id. */
	i: number;
	/** Start time, epoch milliseconds. */
	t: number;
	/** Kind: w, b, h (behaviour) or m. */
	k: "w" | "b" | "h" | "m";
	/** Scenario. */
	s: string;
	/** Source address or range. */
	a: string;
	/** Country code. */
	c: string;
	/** AS organisation. */
	o: string;
	/** First targeted path. */
	p: string;
	/** Decisions and bans the alert carried when read. */
	d: number;
	b: number;
	/** First decision's type. */
	y?: string;
	/** When its last decision ends, epoch milliseconds. */
	u?: number;
	/** The CrowdSec agent that raised it (`machine_id`). Absent when stored by 0.1.0. */
	m?: string;
}

export interface LogRow {
	day: string;
	/** "chunk" as written by a sync step, "part" once merged. */
	part: "chunk" | "part";
	alerts: LogAlert[];
	updatedAt: string;
}

/** Most alerts in one merged row. A day with more takes several. */
export const PART_SIZE = 1500;

const KIND_CODE: Record<Kind, LogAlert["k"]> = { waf: "w", bot: "b", behaviour: "h", manual: "m" };
const CODE_KIND: Record<LogAlert["k"], Kind> = { w: "waf", b: "bot", h: "behaviour", m: "manual" };

export function toLog(row: AlertRow): LogAlert {
	return {
		i: row.id,
		t: Date.parse(row.startedAt),
		k: KIND_CODE[row.kind],
		s: row.scenario,
		a: row.ip,
		c: row.country,
		o: row.asName,
		p: row.path,
		d: row.decisions,
		b: row.bans,
		...(row.decisionType && { y: row.decisionType }),
		...(row.decisionUntil && { u: Date.parse(row.decisionUntil) }),
		...(row.machine && { m: row.machine }),
	};
}

export function kindOfLog(alert: LogAlert): Kind {
	return CODE_KIND[alert.k];
}

export function chunkId(day: string, alerts: LogAlert[]): string {
	return `${day}|c${Math.min(...alerts.map((a) => a.i))}`;
}

export function partId(day: string, n: number): string {
	return `${day}|p${n}`;
}

/** Group alert rows into one chunk per local day. */
export function chunksOf(rows: AlertRow[], now: Date): Array<{ id: string; data: LogRow }> {
	const byDay = new Map<string, LogAlert[]>();
	for (const row of rows) {
		const list = byDay.get(row.day) ?? [];
		list.push(toLog(row));
		byDay.set(row.day, list);
	}
	return [...byDay.entries()].map(([day, alerts]) => ({
		id: chunkId(day, alerts),
		data: { day, part: "chunk", alerts, updatedAt: now.toISOString() },
	}));
}

/** Every alert in the rows, once each: a chunk and a part may both hold one while they are merged. */
export function flatten(rows: LogRow[]): LogAlert[] {
	const seen = new Set<number>();
	const out: LogAlert[] = [];
	for (const row of rows) {
		for (const alert of row.alerts) {
			if (seen.has(alert.i)) continue;
			seen.add(alert.i);
			out.push(alert);
		}
	}
	return out;
}

/** A day's alerts in merged parts of at most `PART_SIZE`, oldest first. */
export function partsOf(day: string, alerts: LogAlert[], now: Date): Array<{ id: string; data: LogRow }> {
	const sorted = [...alerts].sort((a, b) => a.t - b.t || a.i - b.i);
	const out: Array<{ id: string; data: LogRow }> = [];
	for (let i = 0; i * PART_SIZE < sorted.length; i++) {
		out.push({ id: partId(day, i), data: { day, part: "part", alerts: sorted.slice(i * PART_SIZE, (i + 1) * PART_SIZE), updatedAt: now.toISOString() } });
	}
	return out;
}
