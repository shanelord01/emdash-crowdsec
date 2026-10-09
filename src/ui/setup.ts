/**
 * The setup check: every thing the numbers depend on, one sentence each.
 *
 * It runs a fresh login rather than trusting a cached token, so a changed
 * password or a proxy that started refusing shows at once. With changes
 * allowed it also looks up the site's and LAPI's addresses for the ban
 * protections and caches them.
 *
 * Calls: kv.list, settings.list, cron.list, the login, one alert search,
 * then two DNS requests per hostname (two hostnames at most) and the cache
 * write: ten at most.
 */

import type { PluginContext } from "emdash/plugin";

import { problemText, t, type Lang, type MessageKey } from "../i18n.js";
import { LapiClient } from "../lapi/client.js";
import { DNS_KEY, dnsFresh, hostOf, namesToResolve, resolveNames } from "../net/protect.js";
import type { CrowdSecSettings, SettingsResult } from "../settings.js";
import { settingsOf } from "../settings.js";
import { REFRESH_TASK, SYNC_TASK, type Loaded } from "../sync/scheduler.js";
import { fetchMetrics } from "../metrics/fetch.js";
import { KEPT_SERIES } from "../metrics/prom.js";
import { USER_AGENT } from "../version.js";
import { actions, banner, button, code, context, header, table, type SecurityBlock } from "./blocks.js";
import { formatAge } from "./format.js";
import { RANGE_ACTION, SETUP_ACTION } from "./ids.js";

export type CheckId = "source" | "timeZone" | "settings" | "url" | "engineMetrics" | "firewallMetrics" | "login" | "userAgent" | "read" | "changes" | "protections" | "scheduler" | "lastSync";
export type CheckStatus = "ok" | "problem" | "waiting" | "skipped";

export interface Check {
	id: CheckId;
	status: CheckStatus;
	detail: string;
}

const ONESHOT_GRACE_MS = 10 * 60_000;

export async function runSetup(ctx: PluginContext, loaded: Loaded, result: SettingsResult, now: Date, lang: Lang): Promise<Check[]> {
	const settings = settingsOf(result);
	const checks: Check[] = [];
	// kv.list, settings.list and cron.list, then every request and write the checks make.
	const budget = { spent: 3 };
	const counted = ctx.http
		? { ...ctx, http: { fetch: (u: string, init?: RequestInit) => ((budget.spent++, ctx.http!.fetch(u, init))) } }
		: ctx;
	const zoneBad = !result.ok && result.problem.key === "timeZoneInvalid";
	const tasks = ctx.cron ? await ctx.cron.list() : null;

	if (settings.source === "demo") {
		checks.push({ id: "source", status: "ok", detail: t(lang, "sourceDemo") });
		checks.push(zoneCheck(result, settings, lang));
	} else {
		checks.push({ id: "source", status: "ok", detail: t(lang, "sourceLapi") });
		checks.push(zoneCheck(result, settings, lang));
		// With only the zone wrong, the LAPI checks still run: everything else is usable.
		checks.push(...(await lapiChecks(counted as PluginContext, settings, zoneBad ? { ok: true, settings } : result, now, lang)));
		checks.push(...(await protectionChecks(counted as PluginContext, settings, loaded, now, lang, budget)));
	}

	checks.push(...(await metricsChecks(counted as PluginContext, settings, lang, budget)));
	checks.push(schedulerCheck(tasks, loaded, now, lang), lastSyncCheck(loaded, now, lang));
	return checks;
}

function zoneCheck(result: SettingsResult, settings: CrowdSecSettings, lang: Lang): Check {
	if (!result.ok && result.problem.key === "timeZoneInvalid") return { id: "timeZone", status: "problem", detail: problemText(lang, result.problem) };
	return { id: "timeZone", status: "ok", detail: settings.timeZone };
}

async function lapiChecks(ctx: PluginContext, settings: CrowdSecSettings, result: SettingsResult, now: Date, lang: Lang): Promise<Check[]> {
	const skip = (id: CheckId, reason: MessageKey): Check => ({ id, status: "skipped", detail: t(lang, reason) });
	if (!result.ok && result.problem.key === "notConfigured") {
		const detail = [problemText(lang, result.problem)];
		if (result.missing.includes("machinePassword")) detail.push(t(lang, "encryptionHint"));
		return [
			{ id: "settings", status: "problem", detail: detail.join(" ") },
			skip("url", "needsSettings"),
			skip("login", "needsSettings"),
			skip("userAgent", "needsSettings"),
			skip("read", "needsSettings"),
		];
	}
	const out: Check[] = [{ id: "settings", status: "ok", detail: t(lang, "settingsSaved") }];
	if (!result.ok) {
		// The URL itself cannot be used, and `readSettings` never hands it on.
		return [...out, { id: "url", status: "problem", detail: problemText(lang, result.problem) }, skip("login", "needsUrl"), skip("userAgent", "needsUrl"), skip("read", "needsUrl")];
	}
	out.push({ id: "url", status: "ok", detail: settings.lapiUrl });

	if (!ctx.http) return [...out, { id: "login", status: "problem", detail: t(lang, "noNetwork") }];
	const http = ctx.http;
	const client = new LapiClient({
		baseUrl: settings.lapiUrl,
		machineId: settings.machineId,
		password: settings.password,
		fetch: (u, init) => http.fetch(u, init),
	});

	const login = await client.login();
	if (!login.ok) {
		const refused = login.problem.key === "loginRefused";
		return [
			...out,
			{ id: "login", status: "problem", detail: problemText(lang, login.problem) },
			refused
				? { id: "userAgent", status: "problem", detail: t(lang, "userAgentMaybe", { ua: USER_AGENT }) }
				: skip("userAgent", "needsLogin"),
			skip("read", "needsLogin"),
		];
	}
	out.push({ id: "login", status: "ok", detail: t(lang, "loginOk", { machine: settings.machineId }) });
	out.push({ id: "userAgent", status: "ok", detail: t(lang, "userAgentOk", { ua: USER_AGENT }) });

	const read = await client.alerts({ since: new Date(now.getTime() - 3_600_000), limit: 1, simulated: settings.includeSimulated });
	out.push(read.ok ? { id: "read", status: "ok", detail: t(lang, "readOk") } : { id: "read", status: "problem", detail: problemText(lang, read.problem) });
	return out;
}

async function protectionChecks(ctx: PluginContext, settings: CrowdSecSettings, loaded: Loaded, now: Date, lang: Lang, budget: { spent: number }): Promise<Check[]> {
	if (!settings.allowChanges) return [{ id: "changes", status: "ok", detail: t(lang, "changesOffDetail") }];
	const out: Check[] = [{ id: "changes", status: "ok", detail: t(lang, "changesOnDetail") }];
	const names = namesToResolve(ctx.site.url, settings.lapiUrl);
	if (names.length === 0 || !ctx.http) {
		out.push({ id: "protections", status: "ok", detail: t(lang, "protectionsLiteral") });
		return out;
	}
	let dns = dnsFresh(loaded.dns, names, now) ? loaded.dns : null;
	if (!dns) {
		const http = ctx.http;
		const looked = await resolveNames((u, init) => http.fetch(u, init), names, now);
		if (!looked.ok) {
			out.push({ id: "protections", status: "problem", detail: problemText(lang, looked.problem) });
			return out;
		}
		await ctx.kv.set(DNS_KEY, looked.value);
		budget.spent++;
		dns = looked.value;
	}
	const site = hostOf(ctx.site.url);
	const lapi = hostOf(settings.lapiUrl);
	const describe = (host: string | null) => (host ? `${host} (${(dns!.addresses[host] ?? [host]).join(", ")})` : "");
	out.push({
		id: "protections",
		status: "ok",
		detail: t(lang, "protectionsOk", { site: describe(site), lapi: describe(lapi), count: settings.protectedAddresses.length }),
	});
	if (settings.protectedInvalid.length > 0) {
		out.push({ id: "protections", status: "problem", detail: t(lang, "protectedInvalid", { entries: settings.protectedInvalid.join(", ") }) });
	}
	return out;
}

/**
 * One request to each metrics URL: does it answer, and which of the series
 * the charts read does it carry? A check that would pass ten calls waits for
 * the next press: the DNS lookup comes first while its cache is cold.
 */
async function metricsChecks(ctx: PluginContext, settings: CrowdSecSettings, lang: Lang, budget: { spent: number }): Promise<Check[]> {
	const out: Check[] = [];
	for (const [id, url, problem, kind] of [
		["engineMetrics", settings.engineMetricsUrl, settings.metricsProblems.engine, "engine"],
		["firewallMetrics", settings.firewallMetricsUrl, settings.metricsProblems.firewall, "firewall"],
	] as const) {
		if (settings.source === "demo") {
			out.push({ id, status: "ok", detail: t(lang, "sourceDemo") });
			continue;
		}
		if (problem) {
			out.push({ id, status: "problem", detail: problemText(lang, problem) });
			continue;
		}
		if (!url) {
			out.push({ id, status: "skipped", detail: t(lang, "metricsOff") });
			continue;
		}
		if (!ctx.http) {
			out.push({ id, status: "problem", detail: t(lang, "noNetwork") });
			continue;
		}
		if (budget.spent + 1 > 10) {
			out.push({ id, status: "waiting", detail: t(lang, "metricsDeferred") });
			continue;
		}
		const http = ctx.http;
		const res = await fetchMetrics((u, init) => http.fetch(u, init), url);
		if (!res.ok) {
			out.push({ id, status: "problem", detail: problemText(lang, res.problem) });
			continue;
		}
		const names = [...new Set(res.value.map((s) => s.name))].sort();
		const expected = [...KEPT_SERIES].filter((n) => (kind === "firewall" ? n.startsWith("fw_") : n.startsWith("cs_")));
		out.push(
			names.length > 0
				? { id, status: "ok", detail: t(lang, "metricsOk", { count: names.length, names: names.join(", ") }) }
				: { id, status: "problem", detail: t(lang, "metricsNone", { expected: expected.join(", ") }) },
		);
	}
	return out;
}

function schedulerCheck(tasks: Array<{ name: string; schedule: string; nextRunAt: string; lastRunAt: string | null }> | null, loaded: Loaded, now: Date, lang: Lang): Check {
	if (!tasks) return { id: "scheduler", status: "problem", detail: t(lang, "syncUnschedulable") };
	const sync = tasks.find((task) => task.name === SYNC_TASK);
	if (!sync) return { id: "scheduler", status: "problem", detail: t(lang, "schedulerNotScheduled") };
	const minutes = intervalMinutes(sync.schedule);
	const interval = minutes % 60 === 0 ? t(lang, "hours", { count: minutes / 60 }) : t(lang, "minutes", { count: minutes });
	const late = (iso: string | null | undefined, graceMs: number) => Boolean(iso) && now.getTime() - Date.parse(iso!) > graceMs;
	const age = (iso: string) => formatAge(iso, now, lang) ?? iso;

	const refresh = tasks.find((task) => task.name === REFRESH_TASK);
	if (refresh && late(refresh.nextRunAt, ONESHOT_GRACE_MS)) {
		return { id: "scheduler", status: "problem", detail: t(lang, "schedulerRefreshStuck", { age: age(refresh.nextRunAt) }) };
	}
	const grace = 2 * minutes * 60_000;
	if (sync.lastRunAt) {
		if (late(sync.lastRunAt, grace)) return { id: "scheduler", status: "problem", detail: t(lang, "schedulerStale", { age: age(sync.lastRunAt), interval }) };
		return { id: "scheduler", status: "ok", detail: t(lang, "schedulerOk", { age: age(sync.lastRunAt), interval }) };
	}
	if (!loaded.state.lastSync && loaded.waiting && late(loaded.waiting, grace)) {
		return { id: "scheduler", status: "problem", detail: t(lang, "schedulerNeverRan", { age: age(loaded.waiting), interval }) };
	}
	return { id: "scheduler", status: "waiting", detail: t(lang, "schedulerWaiting", { interval }) };
}

function lastSyncCheck(loaded: Loaded, now: Date, lang: Lang): Check {
	const { state } = loaded;
	if (state.lastProblem) {
		const error = problemText(lang, state.lastProblem);
		const at = formatAge(state.lastErrorAt, now, lang);
		return { id: "lastSync", status: "problem", detail: at ? t(lang, "lastAttemptFailedAge", { age: at, error }) : t(lang, "lastAttemptFailed", { error }) };
	}
	const age = formatAge(state.lastSync, now, lang);
	if (!age) return { id: "lastSync", status: "waiting", detail: t(lang, "notSynced") };
	return { id: "lastSync", status: "ok", detail: t(lang, "synced", { age }) };
}

/** Minutes between two runs of one of the offered schedules; fifteen for anything else. */
export function intervalMinutes(schedule: string): number {
	const everyMinutes = /^\*\/(\d+) \* \* \* \*$/.exec(schedule);
	if (everyMinutes) return Number(everyMinutes[1]);
	if (/^0 \* \* \* \*$/.test(schedule)) return 60;
	const everyHours = /^0 \*\/(\d+) \* \* \*$/.exec(schedule);
	if (everyHours) return Number(everyHours[1]) * 60;
	return 15;
}

const CHECK_LABELS: Record<CheckId, MessageKey> = {
	source: "checkSource",
	timeZone: "checkTimeZone",
	engineMetrics: "checkEngineMetrics",
	firewallMetrics: "checkFirewallMetrics",
	settings: "checkSettings",
	url: "checkUrl",
	login: "checkLogin",
	userAgent: "checkUserAgent",
	read: "checkRead",
	changes: "checkChanges",
	protections: "checkProtections",
	scheduler: "checkScheduler",
	lastSync: "checkLastSync",
};

const STATUS_LABELS: Record<CheckStatus, MessageKey> = {
	ok: "statusOk",
	problem: "statusProblem",
	waiting: "statusWaiting",
	skipped: "statusSkipped",
};

const CRON_TRIGGER_SNIPPET = `// wrangler.jsonc
"triggers": { "crons": ["* * * * *"] }`;

export function renderSetup(checks: Check[], backRange: number, lang: Lang): SecurityBlock[] {
	const problems = checks.filter((check) => check.status === "problem").length;
	const out: SecurityBlock[] = [
		actions(
			[
				button(`${RANGE_ACTION}:back`, t(lang, "backToSecurity"), { style: "secondary", value: backRange }),
				button(SETUP_ACTION, t(lang, "checkAgain"), { style: "secondary", value: backRange }),
			],
			{ blockId: "cs:setup:controls" },
		),
		header(t(lang, "setupTitle")),
		problems > 0 ? banner({ description: t(lang, "setupProblems", { count: problems }), variant: "error" }) : banner({ description: t(lang, "setupAllGood") }),
		table({
			blockId: "cs:setup:checks",
			pageActionId: "cs:setup:checks:page",
			columns: [
				{ key: "check", label: t(lang, "colCheck"), format: "text" },
				{ key: "status", label: t(lang, "colStatus"), format: "badge" },
				{ key: "detail", label: t(lang, "colDetails"), format: "text" },
			],
			rows: checks.map((check) => ({
				check: t(lang, CHECK_LABELS[check.id]),
				status: t(lang, STATUS_LABELS[check.status]),
				detail: check.detail,
			})),
		}),
	];
	if (checks.some((check) => check.id === "scheduler" && check.status === "problem")) {
		out.push(context(t(lang, "schedulerHowTo")));
		out.push(code(CRON_TRIGGER_SNIPPET, { language: "jsonc" }));
	}
	return out;
}
