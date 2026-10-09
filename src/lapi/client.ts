/**
 * The CrowdSec Local API, through `ctx.http.fetch`.
 *
 * The client uses exactly the routes the README tells an operator to
 * admit, and no others:
 *
 * - `POST /v1/watchers/login`
 * - `GET /v1/alerts`, `GET /v1/alerts/{id}`
 * - with changes allowed: `POST /v1/alerts`, `DELETE /v1/alerts/{id}`,
 *   `DELETE /v1/decisions/{id}` and `POST /v1/allowlists/check`
 *
 * It never sends `DELETE /v1/decisions` with a filter (with no filter it
 * removes every decision) nor a bulk `DELETE /v1/alerts`, and it never
 * searches with `ip=`, which also matches alerts with an empty source.
 *
 * Every request carries `User-Agent: emdash-crowdsec/<version>`: LAPI
 * refuses a watcher login whose User-Agent is not `name/version`.
 *
 * Redirects are not followed. EmDash's fetch would follow one, and a 307
 * or 308 re-sends the body, which for the login is the machine password,
 * to whatever host the redirect names. Any 3xx is reported instead.
 *
 * The session token is never stored. Each invocation that needs LAPI logs
 * in once and keeps the token in memory for its own requests, so plugin KV
 * never holds a credential.
 */

import { failure } from "../i18n.js";
import { USER_AGENT } from "../version.js";
import type { AlertQuery, RawAlert, Result } from "./types.js";
import { secondsDuration } from "../sync/time.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface LapiConfig {
	baseUrl: string;
	machineId: string;
	password: string;
	fetch: FetchLike;
	now?: () => Date;
	/** LAPI's clock less ours, in milliseconds, as last measured. Durations are worked out on LAPI's clock. */
	skewMs?: number;
}

/** Slack added to the start of a search window, for clock skew the Date header cannot resolve below a second. */
export const SINCE_SLACK_S = 60;

export class LapiClient {
	readonly #config: LapiConfig;
	#token: string | null = null;
	/** Bridge calls this client spent: the login and every request. */
	calls = 0;
	/** LAPI's clock less ours, from the last response's Date header. */
	skewMs: number | undefined;

	constructor(config: LapiConfig) {
		this.#config = config;
		this.skewMs = config.skewMs;
	}

	#now(): Date {
		return this.#config.now?.() ?? new Date();
	}

	/** LAPI's idea of now, which its relative durations are measured from. */
	lapiNow(): Date {
		return new Date(this.#now().getTime() + (this.skewMs ?? 0));
	}

	/** Log in and keep the token for this invocation. */
	async login(): Promise<Result<null>> {
		const res = await this.#request("/v1/watchers/login", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ machine_id: this.#config.machineId, password: this.#config.password, scenarios: [] }),
		});
		if (!res.ok) return res;
		const { response, body } = res.value;
		if (response.status === 401) return failure("loginRefused");
		if (response.status === 403) return failure("routeRefused", { route: "POST /v1/watchers/login" });
		if (response.status === 404) return failure("notLapi");
		if (!response.ok) return httpFailure(response.status, body);
		const data = body as { token?: unknown } | null;
		if (!data || typeof data.token !== "string" || !data.token) return failure("unexpectedAnswer");
		this.#token = data.token;
		return { ok: true, value: null };
	}

	/** `GET /v1/alerts`, newest created first. */
	async alerts(query: AlertQuery): Promise<Result<RawAlert[]>> {
		const res = await this.#authed("GET /v1/alerts", () => `/v1/alerts?${alertSearch(query, this.lapiNow())}`, { method: "GET" });
		if (!res.ok) return res;
		if (res.value === null) return { ok: true, value: [] };
		if (!Array.isArray(res.value)) return failure("unexpectedAnswer");
		return { ok: true, value: res.value as RawAlert[] };
	}

	/** `GET /v1/alerts/{id}`; null when LAPI has no such alert. */
	async alert(id: number): Promise<Result<RawAlert | null>> {
		const res = await this.#authed("GET /v1/alerts/{id}", () => `/v1/alerts/${id}`, { method: "GET" }, { notFound: true });
		if (!res.ok) return res;
		if (res.value === NOT_FOUND) return { ok: true, value: null };
		if (typeof res.value !== "object" || res.value === null) return failure("unexpectedAnswer");
		return { ok: true, value: res.value as RawAlert };
	}

	/** `POST /v1/alerts` with one alert. Answers the new alert's id. */
	async addAlert(alert: Record<string, unknown>): Promise<Result<string>> {
		const res = await this.#authed("POST /v1/alerts", () => "/v1/alerts", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify([alert]),
		});
		if (!res.ok) return res;
		const ids = res.value;
		if (!Array.isArray(ids) || ids.length === 0) return failure("unexpectedAnswer");
		return { ok: true, value: String(ids[0]) };
	}

	/** `DELETE /v1/alerts/{id}`. Answers how many LAPI deleted. */
	async deleteAlert(id: number): Promise<Result<number>> {
		const res = await this.#authed("DELETE /v1/alerts/{id}", () => `/v1/alerts/${id}`, { method: "DELETE" }, { notFound: true });
		if (!res.ok) return res;
		return { ok: true, value: res.value === NOT_FOUND ? 0 : deletedCount(res.value) };
	}

	/** `DELETE /v1/decisions/{id}`, one decision by id and never by filter. */
	async deleteDecision(id: number): Promise<Result<number>> {
		const res = await this.#authed("DELETE /v1/decisions/{id}", () => `/v1/decisions/${id}`, { method: "DELETE" }, { notFound: true });
		if (!res.ok) return res;
		return { ok: true, value: res.value === NOT_FOUND ? 0 : deletedCount(res.value) };
	}

	/**
	 * `POST /v1/allowlists/check` with `{"targets": [value]}`. LAPI answers
	 * `{"results": [{"target", "allowlists": [...]}]}`, a result only for a
	 * target something allowlists, and counts a range as allowlisted when any
	 * address inside it is. The path form (`GET .../check/{value}`) cannot
	 * carry a range through a proxy that decodes `%2F`, so it is not used.
	 *
	 * Fails closed: an answer in any other shape is an error, never "not
	 * allowlisted".
	 */
	async allowlisted(value: string): Promise<Result<{ allowlisted: boolean; reason?: string }>> {
		const res = await this.#authed("POST /v1/allowlists/check", () => "/v1/allowlists/check", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ targets: [value] }),
		});
		if (!res.ok) return res;
		const results = (res.value as { results?: unknown } | null)?.results;
		if (!Array.isArray(results)) return failure("allowlistUnreadable");
		const reasons: string[] = [];
		for (const result of results) {
			const lists = (result as { allowlists?: unknown } | null)?.allowlists;
			if (!Array.isArray(lists) || !lists.every((entry) => typeof entry === "string")) return failure("allowlistUnreadable");
			reasons.push(...(lists as string[]));
		}
		if (reasons.length === 0) return { ok: true, value: { allowlisted: false } };
		return { ok: true, value: { allowlisted: true, reason: reasons.join(", ").slice(0, 200) } };
	}

	/** A request with the invocation's token, logging in first when there is none. */
	async #authed(route: string, path: () => string, init: RequestInit, opts: { notFound?: boolean } = {}): Promise<Result<unknown>> {
		if (!this.#token) {
			const login = await this.login();
			if (!login.ok) return login;
		}
		// The path is built after the login, whose Date header measures the skew.
		const res = await this.#request(path(), {
			...init,
			headers: { ...(init.headers as Record<string, string> | undefined), Authorization: `Bearer ${this.#token}` },
		});
		if (!res.ok) return res;
		const { response, body } = res.value;
		if (response.status === 401) return failure("tokenRefused");
		if (response.status === 403) return failure("routeRefused", { route });
		if (response.status === 404 && opts.notFound) return { ok: true, value: NOT_FOUND };
		if (response.status === 404) return failure("routeMissing", { route });
		if (!response.ok) return httpFailure(response.status, body);
		return { ok: true, value: body };
	}

	async #request(path: string, init: RequestInit): Promise<Result<{ response: Response; body: unknown }>> {
		let response: Response;
		this.calls++;
		const sent = this.#now().getTime();
		try {
			response = await this.#config.fetch(`${this.#config.baseUrl}${path}`, {
				...init,
				redirect: "manual",
				headers: { Accept: "application/json", "User-Agent": USER_AGENT, ...(init.headers as Record<string, string>) },
			});
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			if (/byte limit/i.test(detail)) return failure("tooLarge");
			if (/blocked fetch|internal host/i.test(detail)) return failure("blockedHost");
			if (/redirect/i.test(detail)) return failure("redirected", { status: 0 });
			return failure("unreachable", { detail: detail.slice(0, 200) });
		}

		const date = Date.parse(response.headers.get("date") ?? "");
		if (!Number.isNaN(date)) this.skewMs = date - sent;

		if (response.status >= 300 && response.status < 400) {
			await response.body?.cancel();
			return failure("redirected", { status: response.status });
		}

		const text = await response.text();
		if (!text) return { ok: true, value: { response, body: null } };
		try {
			return { ok: true, value: { response, body: JSON.parse(text) } };
		} catch {
			// A proxy answers its own 401, 403 and 404 pages in HTML. Those still
			// read as the refusal they are. Anything else that is not JSON is not LAPI.
			if (response.status === 401 || response.status === 403 || response.status === 404) {
				return { ok: true, value: { response, body: null } };
			}
			return failure("notJson", { status: response.status });
		}
	}
}

const NOT_FOUND = Symbol("not found");

function deletedCount(body: unknown): number {
	const n = Number((body as { nbDeleted?: unknown } | null)?.nbDeleted ?? 0);
	return Number.isFinite(n) ? n : 0;
}

function httpFailure(status: number, body?: unknown) {
	if (status === 429) return failure("rateLimited");
	const message = (body as { message?: unknown } | null)?.message;
	if (typeof message === "string" && message) return failure("lapiSaid", { status, message: message.slice(0, 200) });
	return failure("httpStatus", { status });
}

/**
 * The query string of one alert search, in a fixed order so tests can name
 * the exact URL. `since` and `until` are durations back from `now`, which is
 * LAPI's clock (ours plus the measured skew). `since` is widened by
 * `SINCE_SLACK_S` because re-reading is harmless: rows are stored by id and
 * counted once. `until` is never widened. Its window's upper bound has
 * been read already by an earlier, overlapping window.
 */
export function alertSearch(query: AlertQuery, now: Date): string {
	const params: string[] = [];
	const add = (key: string, value: string) => params.push(`${key}=${encodeURIComponent(value)}`);
	if (query.since) add("since", secondsDuration((now.getTime() - query.since.getTime()) / 1000 + SINCE_SLACK_S));
	if (query.until) {
		const back = Math.floor((now.getTime() - query.until.getTime()) / 1000);
		if (back > 0) add("until", `${back}s`);
	}
	if (query.scope && query.value) {
		add("scope", query.scope);
		add("value", query.value);
	}
	if (query.activeOnly) add("has_active_decision", "true");
	if (query.origin) add("origin", query.origin);
	add("simulated", query.simulated ? "true" : "false");
	// LAPI includes community blocklist and list alerts unless told not to.
	if (!query.origin && query.blocklists !== "include") add("include_capi", "false");
	add("limit", String(query.limit));
	return params.join("&");
}

/** The LAPI URL as entered, without trailing slashes or a trailing `/v1`. */
export function normalizeBaseUrl(raw: string): string {
	return raw.trim().replace(/\/+$/, "").replace(/\/v1$/i, "");
}
