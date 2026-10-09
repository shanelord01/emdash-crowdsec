/**
 * Community blocklist and list alerts. Pure.
 *
 * CrowdSec's Central API pulls the community blocklist into LAPI as alerts
 * with decisions of origin `CAPI`, and subscribed lists as origin `lists`.
 * One such alert carries thousands of decisions and an empty source. They
 * are not this site's own events: the plugin shows them as one count, never
 * as rows, charts or top lists.
 */

import type { RawAlert, RawDecision } from "./types.js";

export const BLOCKLIST_ORIGINS = ["CAPI", "lists"] as const;

export function isBlocklistDecision(decision: Pick<RawDecision, "origin">): boolean {
	const origin = (decision.origin ?? "").toLowerCase();
	return origin === "capi" || origin === "lists";
}

/**
 * Is this alert the community blocklist or a list, rather than one of the
 * site's own? Any decision of a blocklist origin, or a blocklist source
 * scope (`crowdsecurity/community-blocklist`, `lists:<name>`), says so.
 */
export function isBlocklistAlert(alert: Pick<RawAlert, "decisions" | "source" | "scenario">): boolean {
	if ((alert.decisions ?? []).some(isBlocklistDecision)) return true;
	return isBlocklistScope(alert.source?.scope ?? "") || /^update : /.test(alert.scenario ?? "");
}

export function isBlocklistScope(scope: string): boolean {
	return /community[-_]?blocklist|^lists:/i.test(scope);
}
