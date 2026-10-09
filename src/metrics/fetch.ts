/**
 * Reading a Prometheus endpoint: the security engine's (`:6060/metrics`) or
 * the firewall bouncer's (`:60601/metrics`), each published on a narrow
 * path of a public HTTPS hostname. GET only, no credentials, the plugin's
 * User-Agent, and no redirects followed, as for LAPI.
 */

import { failure } from "../i18n.js";
import type { FetchLike } from "../lapi/client.js";
import type { Result } from "../lapi/types.js";
import { USER_AGENT } from "../version.js";
import { KEPT_SERIES, parsePrometheus, type Series } from "./prom.js";

export async function fetchMetrics(fetch: FetchLike, url: string): Promise<Result<Series[]>> {
	let response: Response;
	try {
		response = await fetch(url, {
			method: "GET",
			redirect: "manual",
			headers: { Accept: "text/plain;version=0.0.4", "User-Agent": USER_AGENT },
		});
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		if (/byte limit/i.test(detail)) return failure("m7c");
		return failure("m7e", { detail: detail.slice(0, 200) });
	}
	if (response.status >= 300 && response.status < 400) {
		await response.body?.cancel();
		return failure("redirected", { status: response.status });
	}
	if (response.status === 403) return failure("m7f");
	if (!response.ok) return failure("m7g", { status: response.status });
	const text = await response.text();
	if (/^\s*</.test(text)) return failure("m7h");
	return { ok: true, value: parsePrometheus(text, KEPT_SERIES) };
}
