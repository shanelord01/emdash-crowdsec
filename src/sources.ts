/**
 * Where alerts come from: the site's CrowdSec LAPI, behind one interface so
 * the sync and the pages can be tested with a source of their own.
 */

import type { PluginContext } from "emdash/plugin";

import { LapiClient } from "./lapi/client.js";
import type { AlertQuery, RawAlert, Result } from "./lapi/types.js";
import type { CrowdSecSettings } from "./settings.js";

export interface Source {
	alerts(query: AlertQuery): Promise<Result<RawAlert[]>>;
	/** Bridge calls the source spent so far in this invocation. */
	calls(): number;
	/** LAPI's clock less ours, as last measured, to store for the next invocation. */
	skew(): number | undefined;
	/** The LAPI client, for writes. Null for a test source. */
	lapi: LapiClient | null;
}

/**
 * The configured source, or null when it cannot work: no network, or LAPI
 * settings that `readSettings` refused (an unusable URL is never handed on).
 */
export function buildSource(
	ctx: PluginContext,
	settings: CrowdSecSettings,
	skewMs?: number,
	opts: { now?: () => Date } = {},
): Source | null {
	if (!ctx.http || !settings.lapiUrl) return null;
	const http = ctx.http;
	const lapi = new LapiClient({
		baseUrl: settings.lapiUrl,
		machineId: settings.machineId,
		password: settings.password,
		fetch: (url, init) => http.fetch(url, init),
		...(skewMs !== undefined && { skewMs }),
		...(opts.now && { now: opts.now }),
	});
	return { alerts: (query) => lapi.alerts(query), calls: () => lapi.calls, skew: () => lapi.skewMs, lapi };
}
