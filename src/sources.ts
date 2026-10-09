/**
 * Where alerts come from: a CrowdSec LAPI, or generated demo data.
 *
 * The demo source answers the same queries with alerts in LAPI's own JSON
 * shape, so the sync, the pages and the tools run the code a real LAPI
 * runs through. It is deterministic: an hour of demo data is the same
 * whenever it is asked for, which is what lets overlapping windows be
 * counted once, as they are for real data.
 */

import type { PluginContext } from "emdash/plugin";

import { LapiClient } from "./lapi/client.js";
import type { AlertQuery, RawAlert, Result } from "./lapi/types.js";
import type { CrowdSecSettings, SourceId } from "./settings.js";

export interface Source {
	id: SourceId;
	alerts(query: AlertQuery): Promise<Result<RawAlert[]>>;
	/** Bridge calls the source spent so far in this invocation. */
	calls(): number;
	/** LAPI's clock less ours, as last measured, to store for the next invocation. */
	skew(): number | undefined;
	/** The LAPI client, for writes. Null for demo data. */
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
	if (settings.source === "demo") return demoSource(opts.now);
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
	return { id: "lapi", alerts: (query) => lapi.alerts(query), calls: () => lapi.calls, skew: () => lapi.skewMs, lapi };
}

// Demo data ------------------------------------------------------------------

interface DemoScenario {
	scenario: string;
	kind: string;
	weight: number;
	ban?: boolean;
}

const SCENARIOS: DemoScenario[] = [
	{ scenario: "crowdsecurity/http-probing", kind: "crowdsec", weight: 14, ban: true },
	{ scenario: "crowdsecurity/http-sensitive-files", kind: "crowdsec", weight: 9, ban: true },
	{ scenario: "crowdsecurity/http-bad-user-agent", kind: "crowdsec", weight: 8, ban: true },
	{ scenario: "crowdsecurity/http-crawl-non_statics", kind: "crowdsec", weight: 5, ban: true },
	{ scenario: "crowdsecurity/http-admin-interface-probing", kind: "crowdsec", weight: 6, ban: true },
	{ scenario: "crowdsecurity/http-path-traversal-probing", kind: "crowdsec", weight: 3, ban: true },
	{ scenario: "crowdsecurity/vpatch-git-config", kind: "waf", weight: 10 },
	{ scenario: "crowdsecurity/vpatch-env-access", kind: "waf", weight: 9 },
	{ scenario: "crowdsecurity/vpatch-CVE-2025-29927", kind: "waf", weight: 4 },
	{ scenario: "crowdsecurity/generic-wordpress-uploads-php", kind: "waf", weight: 5 },
	{ scenario: "crowdsecurity/appsec-bot-challenge-too-many-requests", kind: "crowdsec", weight: 6, ban: true },
	{ scenario: "crowdsecurity/appsec-bot-challenge-failed", kind: "bot-detection", weight: 5 },
];

const TOTAL_WEIGHT = SCENARIOS.reduce((sum, s) => sum + s.weight, 0);

/**
 * Documentation-range addresses (RFC 5737, RFC 3849) with invented network
 * names and documentation AS numbers (RFC 5398), so no real company appears.
 */
const SOURCES = [
	["203.0.113.10", "NL", "Example Cloud Platform", "64496"],
	["203.0.113.24", "US", "Sample Web Services", "64497"],
	["203.0.113.37", "DE", "Placeholder Hosting GmbH", "64498"],
	["203.0.113.51", "CN", "Demo Telecom Backbone", "64499"],
	["203.0.113.66", "SG", "Fictional Droplets Pte", "64500"],
	["203.0.113.80", "RU", "Imaginary Datacentres", "64501"],
	["198.51.100.7", "US", "Pretend Networks Inc", "64502"],
	["198.51.100.19", "FR", "Invented Servers SAS", "64503"],
	["198.51.100.42", "BR", "Exemplo Telecom Ltda", "64504"],
	["198.51.100.88", "IN", "Sample Mobile Broadband", "64505"],
	["198.51.100.120", "VN", "Mock Internet Corp", "64506"],
	["192.0.2.15", "GB", "Testbed Transit Ltd", "64507"],
	["192.0.2.33", "AU", "Example Broadband Pty Ltd", "64508"],
	["192.0.2.78", "KR", "Demo Fibre Co", "64509"],
	["2001:db8::17", "US", "Placeholder Edge Network", "64510"],
	["2001:db8:4::2a", "DE", "Placeholder Hosting GmbH", "64498"],
] as const;

/**
 * Three invented CrowdSec agents reporting to the demo LAPI, as a central
 * LAPI hears from several hosts. The third has a long generated id, as
 * `cscli machines add --auto` makes, so the shortened form shows too.
 */
export const DEMO_ENGINES = ["edge-01", "web-02", "7f3c9a1e2b8d4c6fa0e5b9d2c4f81a37Qx2LmN8pRt5VwZ"] as const;

const AGENTS = [
	"Mozilla/5.0 (compatible; ExampleScanner/1.0)",
	"python-requests/2.32.3",
	"curl/8.9.1",
	"Go-http-client/1.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
];

const PATHS = [
	"/.env",
	"/.git/config",
	"/wp-login.php",
	"/xmlrpc.php",
	"/admin",
	"/phpinfo.php",
	"/wp-content/uploads/shell.php",
	"/config.json",
	"/",
	"/posts/hello-world",
	"/api/v1/users",
	"/server-status",
];

const HOUR_MS = 3_600_000;
const BAN_SECONDS = 4 * 3600;
/** How far back a search without `since` reaches in demo data. */
const DEMO_DEFAULT_REACH_MS = 30 * 24 * HOUR_MS;
/** The id space of one hour: an alert's id is its hour times this plus its index. */
const PER_HOUR = 32;

function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

function goDuration(seconds: number): string {
	const sign = seconds < 0 ? "-" : "";
	let left = Math.abs(Math.round(seconds));
	const h = Math.floor(left / 3600);
	left -= h * 3600;
	const m = Math.floor(left / 60);
	const s = left - m * 60;
	return `${sign}${h > 0 ? `${h}h` : ""}${h > 0 || m > 0 ? `${m}m` : ""}${s}s`;
}

/** The demo alerts that started in one UTC hour, as LAPI would answer them at `now`. */
export function demoHour(hour: number, now: Date): RawAlert[] {
	const rng = mulberry32(hour * 2654435761);
	const daily = 1 + 0.5 * Math.sin((hour / 24) * 2 * Math.PI);
	const count = Math.min(PER_HOUR - 1, Math.floor(4 + 9 * rng() * daily));
	const out: RawAlert[] = [];
	for (let i = 0; i < count; i++) {
		let pick = rng() * TOTAL_WEIGHT;
		const scenario = SCENARIOS.find((s) => (pick -= s.weight) < 0) ?? SCENARIOS[0]!;
		const [ip, cn, asName, asNumber] = SOURCES[Math.floor(rng() * SOURCES.length)]!;
		const path = PATHS[Math.floor(rng() * PATHS.length)]!;
		const start = hour * HOUR_MS + Math.floor(rng() * HOUR_MS);
		const created = start + 1000 + Math.floor(rng() * 5000);
		if (created > now.getTime()) continue;
		const id = hour * PER_HOUR + i;
		const captcha = scenario.ban && rng() < 0.1;
		const machine = DEMO_ENGINES[Math.min(DEMO_ENGINES.length - 1, Math.floor(rng() * rng() * 4))]!;
		const startIso = new Date(start).toISOString();
		const scope = "Ip";
		out.push({
			id,
			machine_id: machine,
			scenario: scenario.scenario,
			kind: scenario.kind,
			message: `Ip ${ip} performed '${scenario.scenario}'`,
			created_at: new Date(created).toISOString(),
			start_at: startIso,
			stop_at: new Date(created).toISOString(),
			events_count: 1 + Math.floor(rng() * 10),
			simulated: false,
			remediation: Boolean(scenario.ban),
			source: { ip, value: ip, scope, cn, as_name: asName, as_number: asNumber },
			decisions: scenario.ban
				? [
						{
							id: id * 2,
							type: captcha ? "captcha" : "ban",
							duration: goDuration((start + BAN_SECONDS * 1000 - now.getTime()) / 1000),
							origin: "crowdsec",
							scenario: scenario.scenario,
							scope,
							value: ip,
							simulated: false,
						},
					]
				: null,
			meta: [
				{ key: "target_uri", value: JSON.stringify([path]) },
				{ key: "target_host", value: JSON.stringify(["www.example.com"]) },
			],
			events: Array.from({ length: Math.min(3, 1 + Math.floor(rng() * 3)) }, (_, e) => ({
				timestamp: new Date(start + e * 1500).toISOString(),
				meta: [
					{ key: "target_host", value: "www.example.com" },
					{ key: "target_uri", value: path },
					{ key: "http_user_agent", value: AGENTS[(id + e) % AGENTS.length]! },
					...(scenario.kind === "waf" ? [{ key: "rule_name", value: scenario.scenario }] : []),
				],
			})),
		});
	}
	return out;
}

/** One demo alert by id, as `GET /v1/alerts/{id}` would answer it, or null. */
export function demoAlert(id: number, now: Date): RawAlert | null {
	if (!Number.isSafeInteger(id) || id <= 0) return null;
	return demoHour(Math.floor(id / PER_HOUR), now).find((alert) => alert.id === id) ?? null;
}

export function demoSource(nowOf: () => Date = () => new Date()): Source {
	return {
		id: "demo",
		lapi: null,
		calls: () => 0,
		skew: () => undefined,
		alerts: async (query) => {
			const now = nowOf();
			const sinceMs = query.since?.getTime() ?? (query.activeOnly ? now.getTime() - BAN_SECONDS * 1000 - HOUR_MS : now.getTime() - DEMO_DEFAULT_REACH_MS);
			const untilMs = Math.min(query.until?.getTime() ?? now.getTime(), now.getTime());
			const found: RawAlert[] = [];
			for (let hour = Math.floor(sinceMs / HOUR_MS); hour <= Math.floor(untilMs / HOUR_MS); hour++) {
				for (const alert of demoHour(hour, now)) {
					const start = Date.parse(alert.start_at!);
					if (start < sinceMs || start > untilMs) continue;
					if (query.value && alert.source?.value !== query.value) continue;
					if (query.activeOnly && !(alert.decisions ?? []).some((d) => !d.duration?.startsWith("-"))) continue;
					found.push(alert);
				}
			}
			found.sort((a, b) => Date.parse(b.created_at!) - Date.parse(a.created_at!) || b.id! - a.id!);
			return { ok: true, value: found.slice(0, query.limit) };
		},
	};
}
