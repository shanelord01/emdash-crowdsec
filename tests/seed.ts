/**
 * Generated LAPI alerts for tests that need volume: a few hundred a day
 * from documentation addresses, invented networks and three engines,
 * deterministic for a given hour. `fakeLapi` answers the plugin's searches
 * from them, as a LAPI would, and `seedStore` writes them straight into
 * the plugin's storage, as a screenshot seed script would.
 */

import type { PluginRuntimeTestHost } from "@emdash-cms/plugin-test";

import type { RawAlert } from "../src/lapi/types.js";
import { chunksOf } from "../src/store/log.js";
import { compactAlert, countInto, emptyDay, trimDay, type AlertRow, type DayRow } from "../src/store/rows.js";
import { parseGoDuration } from "../src/sync/time.js";
import { datasetOf, settingsFrom } from "../src/settings.js";

interface GeneratedScenario {
	scenario: string;
	kind: string;
	weight: number;
	ban?: boolean;
}

const SCENARIOS: GeneratedScenario[] = [
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
	["203.0.113.51", "CN", "Sample Telecom Backbone", "64499"],
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
 * Three invented CrowdSec agents reporting to one LAPI, as a central
 * LAPI hears from several hosts. The third has a long generated id, as
 * `cscli machines add --auto` makes, so the shortened form shows too.
 */
export const ENGINES = ["edge-01", "web-02", "7f3c9a1e2b8d4c6fa0e5b9d2c4f81a37Qx2LmN8pRt5VwZ"] as const;

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

/** The generated alerts that started in one UTC hour, as LAPI would answer them at `now`. */
export function hourOfAlerts(hour: number, now: Date): RawAlert[] {
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
		const machine = ENGINES[Math.min(ENGINES.length - 1, Math.floor(rng() * rng() * 4))]!;
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

/** Every generated alert that started between two instants, newest created first. */
export function alertsBetween(from: number, to: number, now: Date): RawAlert[] {
	const out: RawAlert[] = [];
	for (let hour = Math.floor(from / HOUR_MS); hour <= Math.floor(to / HOUR_MS); hour++) {
		for (const alert of hourOfAlerts(hour, now)) {
			const start = Date.parse(alert.start_at!);
			if (start >= from && start <= to) out.push(alert);
		}
	}
	return out.sort((a, b) => Date.parse(b.created_at!) - Date.parse(a.created_at!) || b.id! - a.id!);
}

/** One generated alert by id, as `GET /v1/alerts/{id}` answers it. */
export function alertById(id: number, now: Date): RawAlert | null {
	return hourOfAlerts(Math.floor(id / PER_HOUR), now).find((alert) => alert.id === id) ?? null;
}

/**
 * A LAPI for `fakeCtx`: the login, and alert searches by `since`, `until`,
 * `limit` and `has_active_decision`, answered from the generated alerts at
 * the instant `now` gives.
 */
export function fakeLapi(now: () => Date) {
	return async (url: string): Promise<Response> => {
		const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", Date: now().toUTCString() } });
		if (url.endsWith("/v1/watchers/login")) return json({ code: 200, token: "t", expire: new Date(now().getTime() + 3_600_000).toISOString() });
		const u = new URL(url);
		if (!u.pathname.endsWith("/v1/alerts")) throw new Error(`unexpected ${url}`);
		const t = now().getTime();
		const back = (key: string) => {
			const raw = u.searchParams.get(key);
			const seconds = raw ? parseGoDuration(raw) : null;
			return seconds === null ? null : t - seconds * 1000;
		};
		const since = back("since") ?? t - 30 * 86_400_000;
		const until = back("until") ?? t;
		let found = alertsBetween(since, until, now());
		if (u.searchParams.get("has_active_decision") === "true") found = found.filter((a) => (a.decisions ?? []).some((d) => (parseGoDuration(d.duration) ?? 0) > 0));
		return json(found.slice(0, Number(u.searchParams.get("limit") ?? 100)));
	};
}

/**
 * Write generated alerts into the plugin's storage as the sync would have:
 * the alert log in one chunk per local day, the day rows that count them,
 * and a state that says the store is complete from `from` to now.
 */
export async function seedStore(runtime: PluginRuntimeTestHost, settings: Record<string, unknown>, from: number, now: Date): Promise<AlertRow[]> {
	const parsed = settingsFrom(new Map(Object.entries(settings)));
	const config = parsed.ok ? parsed.settings : parsed.partial;
	const rows = alertsBetween(from, now.getTime(), now)
		.map((raw) => compactAlert(raw, now, config.timeZone))
		.filter((row): row is AlertRow => row !== null);
	const days = new Map<string, DayRow>();
	for (const row of rows) {
		const day = days.get(row.day) ?? emptyDay(row.day, now);
		countInto(day, row);
		days.set(row.day, day);
	}
	for (const chunk of chunksOf(rows, now)) await runtime.fixtures.plugin.storage("log", chunk.id, chunk.data);
	for (const day of days.values()) await runtime.fixtures.plugin.storage("days", day.date, trimDay(day));
	await runtime.fixtures.plugin.kv("sync.state", {
		dataset: datasetOf(config),
		head: now.toISOString(),
		gaps: [],
		floor: new Date(from).toISOString(),
		lastSync: now.toISOString(),
		logMigrated: true,
	});
	return rows;
}
