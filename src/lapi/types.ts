/**
 * The parts of LAPI's alert JSON this plugin reads. Everything is optional
 * because LAPI omits empty fields, and a WAF alert carries `decisions: null`.
 */

import type { Problem } from "../i18n.js";

export interface RawMeta {
	key?: string;
	value?: string;
}

export interface RawDecision {
	id?: number;
	type?: string;
	duration?: string;
	origin?: string;
	scenario?: string;
	scope?: string;
	value?: string;
	simulated?: boolean;
}

export interface RawSource {
	ip?: string;
	range?: string;
	as_name?: string;
	as_number?: string;
	cn?: string;
	scope?: string;
	value?: string;
}

export interface RawAlert {
	id?: number;
	uuid?: string;
	scenario?: string;
	kind?: string;
	message?: string;
	created_at?: string;
	start_at?: string;
	stop_at?: string;
	events_count?: number;
	simulated?: boolean;
	remediation?: boolean;
	source?: RawSource;
	decisions?: RawDecision[] | null;
	meta?: RawMeta[] | null;
	events?: Array<{ meta?: RawMeta[] | null; timestamp?: string }> | null;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: string; problem: Problem };

/** One search of `GET /v1/alerts`. Times are absolute; the client turns them into LAPI's relative durations. */
export interface AlertQuery {
	/** Alerts that started at or after this time. */
	since?: Date;
	/** Alerts that started at or before this time. */
	until?: Date;
	limit: number;
	scope?: "Ip" | "Range";
	value?: string;
	simulated?: boolean;
	activeOnly?: boolean;
	/**
	 * Community blocklist (CAPI) and list alerts. Left out unless asked for:
	 * they are not this site's own events, and one of them carries thousands
	 * of decisions. A lookup of one address includes them, so it can say the
	 * address is on the blocklist.
	 */
	blocklists?: "exclude" | "include";
	/** Only alerts with a decision of this origin. Implies `blocklists: "include"`. */
	origin?: "CAPI" | "lists";
}
