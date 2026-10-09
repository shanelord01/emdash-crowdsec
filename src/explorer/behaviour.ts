/**
 * The behaviour an alert's scenario shows, for the Alerts explorer. Pure.
 *
 * CrowdSec's Console tags scenarios with behaviours from its hub metadata,
 * which the plugin does not fetch. This small table reads the scenario name
 * instead. The first rule that matches wins:
 *
 * | Scenario name | Behaviour |
 * | --- | --- |
 * | `vpatch-*`, `appsec-vpatch`, or a CVE id (`cve-2025-29927`, `CVE-2017-9841`) | HTTP exploit |
 * | `http-*probing`, `http-sensitive-files`, `http-path-traversal*` | HTTP scan |
 * | `http-crawl*`, `http-bad-user-agent` | HTTP crawl |
 * | `appsec-bot-challenge*`, `rejected-browser-submission` | Bot |
 * | anything with `ssh` | SSH brute force |
 * | a manual ban (`manual '...'`) | Manual |
 * | anything else | Generic |
 *
 * The vendor prefix (`crowdsecurity/`) is ignored.
 */

export const BEHAVIOURS = ["http-exploit", "http-scan", "http-crawl", "bot", "ssh-bf", "manual", "generic"] as const;
export type Behaviour = (typeof BEHAVIOURS)[number];

const RULES: Array<[RegExp, Behaviour]> = [
	[/^manual '/, "manual"],
	[/(^|\/)(vpatch-|appsec-vpatch)|cve-\d{4}-\d+/i, "http-exploit"],
	[/(^|\/)http-[a-z0-9-]*probing|(^|\/)http-sensitive-files|(^|\/)http-path-traversal/i, "http-scan"],
	[/(^|\/)http-crawl|(^|\/)http-bad-user-agent/i, "http-crawl"],
	[/(^|\/)appsec-bot-challenge|(^|\/)rejected-browser-submission/i, "bot"],
	[/ssh/i, "ssh-bf"],
];

export function behaviourOf(scenario: string): Behaviour {
	for (const [rule, behaviour] of RULES) if (rule.test(scenario)) return behaviour;
	return "generic";
}

export function isBehaviour(value: unknown): value is Behaviour {
	return typeof value === "string" && (BEHAVIOURS as readonly string[]).includes(value);
}
