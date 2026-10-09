/**
 * Turning Prometheus series into the plugin's own counters. Pure.
 *
 * Both sources count from when their process started: the firewall bouncer
 * resets on restart, the security engine on restart and reload. So the plugin
 * keeps the last raw sample and stores the difference to the next one. A
 * counter that went down was reset, and its new value is what it counted
 * since. The first sample only sets the baseline.
 *
 * The bouncer's packet and byte series are typed `gauge` in its output, but
 * they only grow until a restart, so they are read as counters too.
 */

import type { Series } from "./prom.js";

/** Who a decision came from, as the charts group it. */
export type OriginGroup = "community" | "detections" | "manual" | "other";
export const ORIGIN_GROUPS: OriginGroup[] = ["community", "detections", "manual", "other"];

export function originGroup(origin: string | undefined): OriginGroup {
	const o = (origin ?? "").toLowerCase();
	if (o === "capi" || o === "lists" || o.startsWith("lists:")) return "community";
	if (o === "crowdsec") return "detections";
	if (o === "cscli" || o.startsWith("cscli")) return "manual";
	return "other";
}

/** Counter totals by key: `drop.packets.<group>`, `proc.bytes`, `as.reqs`, `ch.requested` and so on. */
export type Counters = Record<string, number>;

export interface Gauges {
	/** Active decisions by origin group, from the engine. */
	bansByOrigin: Record<OriginGroup, number>;
	/** Active community blocklist decisions by reason (`http:scan`, `ssh:bruteforce`). */
	communityReasons: Record<string, number>;
}

export interface Sample {
	at: string;
	counters: Counters;
	gauges: Gauges | null;
	/** Which sources answered. */
	engine: boolean;
	firewall: boolean;
}

const CHALLENGE: Record<string, string> = {
	cs_appsec_challenge_requested_total: "ch.requested",
	cs_appsec_challenge_submitted_total: "ch.submitted",
	cs_appsec_challenge_accepted_total: "ch.accepted",
	cs_appsec_challenge_rejected_total: "ch.rejected",
	cs_appsec_challenge_exempt_total: "ch.exempt",
};

export const CHALLENGE_STAGES = ["requested", "submitted", "accepted", "rejected", "exempt"] as const;

function add(map: Record<string, number>, key: string, value: number): void {
	map[key] = (map[key] ?? 0) + value;
}

/** The counters and gauges of one sample, summed over the labels the charts do not split by. */
export function sampleOf(engine: Series[] | null, firewall: Series[] | null, at: Date): Sample {
	const counters: Counters = {};
	for (const s of firewall ?? []) {
		if (s.name === "fw_bouncer_dropped_packets") add(counters, `drop.packets.${originGroup(s.labels.origin)}`, s.value);
		else if (s.name === "fw_bouncer_dropped_bytes") add(counters, `drop.bytes.${originGroup(s.labels.origin)}`, s.value);
		else if (s.name === "fw_bouncer_processed_packets") add(counters, "proc.packets", s.value);
		else if (s.name === "fw_bouncer_processed_bytes") add(counters, "proc.bytes", s.value);
	}
	let gauges: Gauges | null = null;
	if (engine) {
		gauges = { bansByOrigin: { community: 0, detections: 0, manual: 0, other: 0 }, communityReasons: {} };
		for (const s of engine) {
			if (s.name === "cs_appsec_reqs_total") add(counters, "as.reqs", s.value);
			else if (s.name === "cs_appsec_block_total") add(counters, "as.blocks", s.value);
			else if (s.name === "cs_parser_hits_total") add(counters, "parser.hits", s.value);
			else if (CHALLENGE[s.name]) add(counters, CHALLENGE[s.name]!, s.value);
			else if (s.name === "cs_active_decisions") {
				const group = originGroup(s.labels.origin);
				gauges.bansByOrigin[group] += s.value;
				if (group === "community" && s.labels.reason) add(gauges.communityReasons, s.labels.reason, s.value);
			}
		}
	}
	return { at: at.toISOString(), counters, gauges, engine: engine !== null, firewall: firewall !== null };
}

/**
 * What each counter counted between two samples. A counter lower than
 * before was reset, so its whole new value counts. A key the earlier sample
 * did not have counts from zero when `newCounts` says its source answered
 * then (a new origin appeared), and otherwise only sets its baseline: a
 * source that was down at the last sample has its whole history in its
 * first answer. Keys the later sample lacks count nothing.
 */
export function deltaOf(before: Counters, after: Counters, newCounts: (key: string) => boolean = () => true): Counters {
	const out: Counters = {};
	for (const [key, value] of Object.entries(after)) {
		const prev = before[key];
		if (prev === undefined && !newCounts(key)) continue;
		const delta = prev === undefined || value < prev ? value : value - prev;
		if (delta > 0) out[key] = delta;
	}
	return out;
}

export function isFirewallKey(key: string): boolean {
	return key.startsWith("drop.") || key.startsWith("proc.");
}

/** The last known value of every counter: the new sample's, and the earlier one's for keys a silent source did not report. */
export function carried(before: Counters, after: Sample): Counters {
	const keep: Counters = {};
	for (const [key, value] of Object.entries(before)) {
		const fromFirewall = isFirewallKey(key);
		if ((fromFirewall && !after.firewall) || (!fromFirewall && !after.engine)) keep[key] = value;
	}
	return { ...keep, ...after.counters };
}

export function sumCounters(list: Counters[]): Counters {
	const out: Counters = {};
	for (const c of list) for (const [k, v] of Object.entries(c)) out[k] = (out[k] ?? 0) + v;
	return out;
}

/** Packets or bytes discarded, by origin group, from a set of counters. */
export function discarded(c: Counters, unit: "packets" | "bytes"): Record<OriginGroup, number> & { total: number } {
	const by = { community: 0, detections: 0, manual: 0, other: 0 };
	for (const group of ORIGIN_GROUPS) by[group] = c[`drop.${unit}.${group}`] ?? 0;
	return { ...by, total: by.community + by.detections + by.manual + by.other };
}
