/**
 * Hooks, the cron dispatcher, the admin route and the MCP tools' routes.
 *
 * Hooks and routes live here rather than in `emdash-plugin.jsonc`, whose
 * authored form rejects both. The build probes this module and writes them
 * into the wire manifest.
 *
 * The `admin` route's `permission` is the load-bearing line. A route
 * without one falls back to `plugins:manage`, which is admin-only, so the
 * widget and pages would be blank for editors. `plugins:read` is EDITOR
 * and above. The admin UI sends every page and widget interaction to this
 * one route, so writes cannot sit on a route of their own there: each write
 * checks the host-attested `routeCtx.user` for the administrator role
 * (see `src/write/actions.ts`). The MCP write tools do have their own
 * routes, with `plugins:manage`, which the host enforces.
 */

import type { PluginContext, SandboxedPlugin } from "emdash/plugin";

import { langOf, problemText, t, type Lang } from "./i18n.js";
import { readSettings, settingsOf, type CrowdSecSettings, type SettingsResult } from "./settings.js";
import { buildSource } from "./sources.js";
import { callerAddresses } from "./net/protect.js";
import { isBlocklistDecision } from "./lapi/blocklist.js";
import { sameNetwork } from "./net/ip.js";
import { parseGoDuration } from "./sync/time.js";
import {
	ACTIVE_BATCH,
	BANS_TASK,
	BLOCKLIST_NOW_TASK,
	BLOCKLIST_TASK,
	CATCH_UP_TASKS,
	METRICS_TASK,
	metricsOn,
	runMetrics,
	ensureScheduled,
	loadKv,
	noteWaiting,
	RECONCILE_TASK,
	REFRESH_TASK,
	requestTask,
	runBlocklistCount,
	runReconcile,
	runSync,
	SYNC_TASK,
	type Loaded,
} from "./sync/scheduler.js";
import { addDays, localDay } from "./sync/time.js";
import { mcpTools } from "./tools/declare.js";
import {
	activeDecisions,
	addressAlerts,
	banAddressTool,
	deleteAlertTool,
	removeBanTool,
	securitySummary,
	TOOL_ROUTES,
	topThreats,
	trafficSummary,
} from "./tools/load.js";
import { loadAlerts, parseAlertsInput, renderAlerts, scenariosOf, type AlertsView } from "./ui/alerts.js";
import { decisionRows, parseDecisionsView, protectedView, readActive, renderDecisions, type DecisionsView } from "./ui/decisions.js";
import {
	ALERTS_PATH,
	BAN_CONFIRM,
	BAN_REVIEW,
	DECISIONS_PATH,
	DECISIONS_REMOVE,
	PAGE_REFRESH,
	SECURITY_PATH,
	SETUP_ACTION,
	WIDGET_REFRESH,
} from "./ui/ids.js";
import { DEFAULT_RANGE, loadDays, loadTraffic, parseRange, readSince, renderSecurity, type RangeDays } from "./ui/security.js";
import { renderSetup, runSetup } from "./ui/setup.js";
import { renderWidget } from "./ui/widget.js";
import { asRecord } from "./values.js";
import { addBan, canWrite, checkAllowlist, checkBan, deleteAlert, parseBanInput, removeDecision, writeGate, type BanCheck, type BanInput, type Caller } from "./write/actions.js";

/** The cron hook's timeout. A step with a login and a 3 MB answer can pass the default 5 s on a cold isolate. */
const CRON_TIMEOUT_MS = 30_000;

/** Bridge calls per sandboxed invocation. */
const BUDGET = 10;

/** The worst case of the Decisions page's live read: the login and three searches. */
const LIVE_READ = 4;

type Toast = { message: string; type: "success" | "error" };

interface AdminRouteContext {
	input: unknown;
	user?: Caller["user"];
	requestMeta?: unknown;
	request?: { headers?: Record<string, string> };
	ui?: { locale?: string };
}

const plugin: SandboxedPlugin = {
	hooks: {
		/** Fires only when an administrator clicks Enable, so it is not the only place scheduling happens. */
		"plugin:activate": async (_event, ctx) => {
			await scheduleFromSettings(ctx);
		},

		cron: {
			timeout: CRON_TIMEOUT_MS,
			handler: async (event, ctx) => {
				if (event.name === SYNC_TASK) {
					await runSync(ctx, new Date(), "scheduled");
					return;
				}
				if (event.name === REFRESH_TASK) {
					await runSync(ctx, new Date(), "refresh");
					return;
				}
				if (event.name === BANS_TASK) {
					await runSync(ctx, new Date(), "bans");
					return;
				}
				if ((CATCH_UP_TASKS as readonly string[]).includes(event.name)) {
					await runSync(ctx, new Date(), "catchup", event.name);
					return;
				}
				if (event.name === METRICS_TASK) {
					await runMetrics(ctx);
					return;
				}
				if (event.name === BLOCKLIST_TASK || event.name === BLOCKLIST_NOW_TASK) {
					await runBlocklistCount(ctx);
					return;
				}
				if (event.name === RECONCILE_TASK) {
					const settings = settingsOf(await readSettings(ctx));
					await runReconcile(ctx, settings);
				}
			},
		},
	},

	routes: {
		admin: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await handleAdmin(routeCtx as AdminRouteContext, ctx),
		},

		[TOOL_ROUTES.summary]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await securitySummary(ctx, routeCtx.input, new Date()),
		},
		[TOOL_ROUTES.top]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await topThreats(ctx, routeCtx.input, new Date()),
		},
		[TOOL_ROUTES.decisions]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await activeDecisions(ctx, routeCtx.input, new Date()),
		},
		[TOOL_ROUTES.ipAlerts]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await addressAlerts(ctx, routeCtx.input, new Date()),
		},

		[TOOL_ROUTES.traffic]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await trafficSummary(ctx, routeCtx.input, new Date()),
		},

		// Writes: administrators only, enforced by the host.
		[TOOL_ROUTES.ban]: {
			permission: "plugins:manage",
			handler: async (routeCtx, ctx) => await banAddressTool(ctx, routeCtx as AdminRouteContext, new Date()),
		},
		[TOOL_ROUTES.removeBan]: {
			permission: "plugins:manage",
			handler: async (routeCtx, ctx) => await removeBanTool(ctx, routeCtx as AdminRouteContext),
		},
		[TOOL_ROUTES.deleteAlert]: {
			permission: "plugins:manage",
			handler: async (routeCtx, ctx) => await deleteAlertTool(ctx, routeCtx as AdminRouteContext),
		},
	},

	mcp: { tools: mcpTools() },
};

/**
 * Schedule with the configured interval. Called from activation and from
 * every widget load, because a plugin registered in `plugins: []` never
 * gets `plugin:activate`. `schedule` upserts, so repeating it is harmless.
 */
async function scheduleFromSettings(ctx: PluginContext, settings?: CrowdSecSettings): Promise<void> {
	let known = settings;
	if (!known) {
		try {
			known = settingsOf(await readSettings(ctx));
		} catch {
			known = undefined;
		}
	}
	await ensureScheduled(ctx, known?.syncInterval ?? "*/15 * * * *", known ? metricsOn(known) : false);
}

function callerOf(routeCtx: AdminRouteContext): Caller {
	return { user: routeCtx.user ?? null, requestMeta: routeCtx.requestMeta, request: routeCtx.request, channel: "admin" };
}

async function handleAdmin(routeCtx: AdminRouteContext, ctx: PluginContext) {
	const input = asRecord(routeCtx.input);
	const now = new Date();
	// English when the host passes no locale.
	const lang = langOf(routeCtx.ui?.locale);
	const loaded = await loadKv(ctx);
	const result = await readSettings(ctx);
	const settings = settingsOf(result);
	const caller = callerOf(routeCtx);
	const page = typeof input.page === "string" ? input.page : "";
	const actionId = typeof input.action_id === "string" ? input.action_id : "";

	if (page === SECURITY_PATH) return await securityPage(ctx, input, actionId, loaded, result, now, lang);
	if (page === ALERTS_PATH) return await alertsPage(ctx, input, loaded, result, caller, now, lang);
	if (page === DECISIONS_PATH) return await decisionsPage(ctx, input, actionId, loaded, result, caller, now, lang);

	// The widget.
	const widgetOf = async () => {
		const traffic = metricsOn(settings) ? await loadTraffic(ctx, addDays(localDay(now, settings.timeZone), -13)) : undefined;
		return renderWidget({
			state: loaded.state,
			source: settings.source,
			zone: settings.timeZone,
			now,
			lang,
			...(traffic && { traffic }),
			...(loaded.metrics && { sampledSince: loaded.metrics.since }),
		});
	};
	if (input.type === "block_action" && actionId === WIDGET_REFRESH) {
		const toast = await requestRefresh(ctx, result, now, lang);
		return { blocks: await widgetOf(), toast };
	}
	// Every dashboard visit schedules, the entry point a `plugins: []` install relies on.
	await scheduleFromSettings(ctx, settings);
	await noteWaiting(ctx, loaded, now);
	// The blocklist is counted daily. Before its first count, ask for one now.
	if (result.ok && settings.source === "lapi" && !loaded.blocklist) await requestTask(ctx, BLOCKLIST_NOW_TASK, now);
	return { blocks: await widgetOf() };
}

/** Refresh schedules a step rather than running one: a route has the same ten calls and still has to render. */
async function requestRefresh(ctx: PluginContext, result: SettingsResult, now: Date, lang: Lang): Promise<Toast> {
	// An incomplete configuration is answered at once: the step could only record the same problem.
	if (!result.ok) return { message: problemText(lang, result.problem), type: "error" };
	if (!(await requestTask(ctx, REFRESH_TASK, now))) return { message: t(lang, "syncUnschedulable"), type: "error" };
	await requestTask(ctx, BANS_TASK, new Date(now.getTime() + 30_000));
	return { message: t(lang, "syncRequested"), type: "success" };
}

/** Calls: kv.list, settings.list, two day queries; Refresh adds two schedules; the setup check is its own budget. */
async function securityPage(
	ctx: PluginContext,
	input: Record<string, unknown>,
	actionId: string,
	loaded: Loaded,
	result: SettingsResult,
	now: Date,
	lang: Lang,
) {
	const settings = settingsOf(result);
	const isAction = input.type === "block_action";
	const range: RangeDays = isAction ? parseRange(input.value) : DEFAULT_RANGE;
	// Each range button has an id of its own (`cs:range:24h`), and every one carries its range as its value.
	if (isAction && actionId === SETUP_ACTION) {
		const checks = await runSetup(ctx, loaded, result, now, lang);
		return { blocks: renderSetup(checks, range, lang) };
	}
	let toast: Toast | undefined;
	if (isAction && actionId === PAGE_REFRESH) toast = await requestRefresh(ctx, result, now, lang);
	const since = readSince(range, localDay(now, settings.timeZone));
	const days = await loadDays(ctx, since);
	const on = metricsOn(settings);
	const traffic = on && range !== 1 ? await loadTraffic(ctx, since) : [];
	const blocks = renderSecurity({
		state: loaded.state,
		source: settings.source,
		zone: settings.timeZone,
		range,
		days,
		traffic,
		metrics: loaded.metrics,
		metricsOn: on,
		now,
		lang,
	});
	return toast ? { blocks, toast } : { blocks };
}

/**
 * Calls: kv.list, settings.list, then the 30 days' scenario list and one
 * page of alerts. A delete spends its share first (the login, the GET, the
 * DELETE and the stored row), and the page is read with what is left.
 */
async function alertsPage(
	ctx: PluginContext,
	input: Record<string, unknown>,
	loaded: Loaded,
	result: SettingsResult,
	caller: Caller,
	now: Date,
	lang: Lang,
) {
	const settings = settingsOf(result);
	const { view, deleteId } = parseAlertsInput(input);
	let spent = 2;
	let toast: Toast | undefined;

	if (deleteId !== undefined) {
		const gate = writeGate(settings, caller);
		if (!gate.ok) toast = { message: problemText(lang, gate.problem), type: "error" };
		else if (!result.ok) toast = { message: problemText(lang, result.problem), type: "error" };
		else {
			const lapi = buildSource(ctx, settings, loaded.state.skewMs)?.lapi;
			if (!lapi) toast = { message: t(lang, "noNetwork"), type: "error" };
			else {
				const res = await deleteAlert(ctx, lapi, deleteId, BUDGET - spent);
				spent += lapi.calls + (res.ok ? 1 : 0);
				toast = res.ok
					? { message: problemText(lang, { key: "alertDeleted", params: { id: res.value.id } }), type: "success" }
					: { message: problemText(lang, res.problem), type: "error" };
			}
		}
	}

	const left = BUDGET - spent;
	const scenarios = left >= 2 ? scenariosOf(await loadDays(ctx, addDays(localDay(now, settings.timeZone), -29))) : [];
	const listed = left >= 1 ? await loadAlerts(ctx, view as AlertsView) : { rows: [] };
	const blocks = renderAlerts({
		view,
		...listed,
		scenarios,
		state: loaded.state,
		source: settings.source,
		zone: settings.timeZone,
		canDelete: canWrite(settings, caller),
		now,
		lang,
	});
	return toast ? { blocks, toast } : { blocks };
}

/**
 * Calls: kv.list, settings.list, then the live read: the login and up to
 * three searches. A write spends its share first (see
 * `src/write/actions.ts`), schedules a fresh ban count when a call is left,
 * and the list is read again only when the calls left cover the read at
 * its worst.
 */
async function decisionsPage(
	ctx: PluginContext,
	input: Record<string, unknown>,
	actionId: string,
	loaded: Loaded,
	result: SettingsResult,
	caller: Caller,
	now: Date,
	lang: Lang,
) {
	const settings = settingsOf(result);
	const view: DecisionsView = parseDecisionsView(input);
	const base = actionId.split("|")[0];
	const writer = canWrite(settings, caller);
	const source = result.ok ? buildSource(ctx, settings, loaded.state.skewMs) : null;
	let toast: Toast | undefined;
	let review: { check: BanCheck; input: BanInput } | undefined;
	let wrote = false;
	// Calls the source does not count: a DNS lookup and a schedule.
	let extra = 0;
	const spentOn = () => 2 + (source?.calls() ?? 0) + extra;

	const isWrite = base === BAN_REVIEW || base === BAN_CONFIRM || base === DECISIONS_REMOVE;
	if (isWrite) {
		const gate = writeGate(settings, caller);
		if (!gate.ok) toast = { message: problemText(lang, gate.problem), type: "error" };
		else if (!result.ok) toast = { message: problemText(lang, result.problem), type: "error" };
		else if (!source?.lapi) toast = { message: t(lang, "noNetwork"), type: "error" };
		else if (base === BAN_REVIEW || base === BAN_CONFIRM) {
			const values = base === BAN_REVIEW ? asRecord(input.values) : asRecord(input.value);
			const parsed = parseBanInput(values);
			if (!parsed.ok) toast = { message: problemText(lang, parsed.problem), type: "error" };
			else if (base === BAN_REVIEW) {
				const dnsBefore = loaded.dns;
				const checked = await checkBan(ctx, settings, dnsBefore, caller, parsed.value.value, now);
				if (!checked.ok) {
					// A cold DNS cache was just filled: two requests per name and the write.
					if (checked.problem.key === "dnsJustLoaded") extra += 5;
					toast = { message: problemText(lang, checked.problem), type: "error" };
				} else {
					// The review runs every rule the ban will, the allowlist included.
					const allow = await checkAllowlist(source.lapi, checked.value.value);
					if (!allow.ok) toast = { message: problemText(lang, allow.problem), type: "error" };
					else {
						// And says when the community blocklist already blocks the address.
						// Informational: a failed lookup leaves the note out.
						const look = await source.lapi.alerts({
							scope: checked.value.scope,
							value: checked.value.value,
							activeOnly: true,
							limit: 20,
							simulated: true,
							blocklists: "include",
						});
						const blocklisted =
							look.ok &&
							look.value.some((alert) =>
								(alert.decisions ?? []).some((d) => isBlocklistDecision(d) && sameNetwork(d.value, checked.value.value) && (parseGoDuration(d.duration) ?? 0) > 0),
							);
						review = { check: checked.value, input: parsed.value, ...(blocklisted && { blocklisted }) };
					}
				}
			} else {
				const res = await addBan(ctx, source.lapi, settings, loaded.dns, caller, parsed.value, now);
				if (!res.ok) {
					if (res.problem.key === "dnsJustLoaded") extra += 5;
					toast = { message: problemText(lang, res.problem), type: "error" };
				} else {
					wrote = true;
					toast = {
						message: problemText(lang, {
							key: res.value.ownChecked ? "banDone" : "banDoneUnchecked",
							params: { type: res.value.type, value: res.value.value, duration: res.value.duration },
						}),
						type: "success",
					};
				}
			}
		} else {
			const res = await removeDecision(source.lapi, input.value);
			if (res.ok) wrote = true;
			toast = res.ok
				? { message: problemText(lang, { key: "decisionRemoved", params: { id: res.value.id } }), type: "success" }
				: { message: problemText(lang, res.problem), type: "error" };
		}
	}

	// A fresh ban count for the widget, when a call is left for it.
	if (wrote && spentOn() < BUDGET && (await requestTask(ctx, BANS_TASK, now))) extra += 1;
	const spent = spentOn();

	let rows: ReturnType<typeof decisionRows> | null = null;
	let truncated = false;
	let read = 0;
	let error: string | undefined;
	if (!result.ok) error = problemText(lang, result.problem);
	else if (!source) error = t(lang, "noNetwork");
	else if (spent + LIVE_READ <= BUDGET) {
		const res = await readActive(source, settings, loaded.state.activeBatch ?? ACTIVE_BATCH);
		if (res.ok) {
			rows = decisionRows(res.value.alerts, now);
			truncated = res.value.truncated;
			read = res.value.read;
		} else error = problemText(lang, res.problem);
	}

	const blocks = renderDecisions({
		rows,
		truncated,
		read,
		...(error && { error }),
		view,
		canWrite: writer,
		...(writer && {
			protectedSet: protectedView({ callers: callerAddresses(caller), siteUrl: ctx.site.url, settings, dns: loaded.dns }),
		}),
		...(review && { review }),
		blocklist: loaded.blocklist,
		zone: settings.timeZone,
		now,
		lang,
	});
	return toast ? { blocks, toast } : { blocks };
}

export default plugin;
