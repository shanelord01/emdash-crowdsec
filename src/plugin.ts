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
import {
	ACTIVE_BATCH,
	BANS_TASK,
	BLOCKLIST_NOW_TASK,
	BLOCKLIST_TASK,
	CATCH_UP_TASKS,
	METRICS_TASK,
	metricsOn,
	samplerOn,
	runMetrics,
	ensureScheduled,
	loadKv,
	noteWaiting,
	RECONCILE_TASK,
	REFRESH_TASK,
	requestTask,
	runBlocklistCount,
	runMaintenance,
	runSync,
	SYNC_TASK,
	type Loaded,
	VISIT_PREFIX,
} from "./sync/scheduler.js";
import { addDays, localDay } from "./sync/time.js";
import { mcpTools } from "./tools/declare.js";
import {
	activeDecisions,
	addressAlerts,
	alertsExplorer,
	banAddressTool,
	deleteAlertTool,
	removeBanTool,
	securitySummary,
	TOOL_ROUTES,
	topThreats,
	trafficSummary,
} from "./tools/load.js";
import { loadExplorer, parseExplorerInput, renderExplorer, X_BAN_CONFIRM, X_BAN_REVIEW, X_DELETE, X_UNBAN } from "./ui/explorer.js";
import { rangeOf } from "./explorer/model.js";
import { demoAlert } from "./sources.js";
import type { RawAlert } from "./lapi/types.js";
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
import { DEFAULT_RANGE, loadDays, metricsFor, parseRange, trafficFor, readSince, renderSecurity, type RangeDays } from "./ui/security.js";
import { renderSetup, runSetup } from "./ui/setup.js";
import { renderWidget } from "./ui/widget.js";
import { asRecord } from "./values.js";
import { isBlocklistAlert } from "./lapi/blocklist.js";
import { runWrite, type Toast, type WriteAsk, type WriteOutcome } from "./write/run.js";
import { canWrite, writeMode, type Caller } from "./write/actions.js";

/** The cron hook's timeout. A step with a login and a 3 MB answer can pass the default 5 s on a cold isolate. */
const CRON_TIMEOUT_MS = 30_000;

/** Bridge calls per sandboxed invocation. */
const BUDGET = 10;

/** The worst case of the Decisions page's live read: the login and three searches. */
const LIVE_READ = 4;


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
					await runMaintenance(ctx);
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
		[TOOL_ROUTES.explorer]: {
			permission: "plugins:read",
			handler: async (routeCtx, ctx) => await alertsExplorer(ctx, routeCtx.input, new Date()),
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
	await ensureScheduled(ctx, known?.syncInterval ?? "*/15 * * * *", known ? samplerOn(known) : false);
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
	if (page === ALERTS_PATH) return await explorerPage(ctx, input, loaded, result, caller, now, lang);
	if (page === DECISIONS_PATH) return await decisionsPage(ctx, input, actionId, loaded, result, caller, now, lang);

	// The widget.
	const widgetOf = async () => {
		const traffic = metricsOn(settings) ? await trafficFor(ctx, settings, addDays(localDay(now, settings.timeZone), -13), now) : undefined;
		const metrics = metricsFor(loaded.metrics, settings, now);
		return renderWidget({
			state: loaded.state,
			source: settings.source,
			zone: settings.timeZone,
			now,
			lang,
			...(traffic && { traffic }),
			...(metrics && { sampledSince: metrics.since }),
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
	if (result.ok && !loaded.blocklist) await requestTask(ctx, BLOCKLIST_NOW_TASK, now);
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
	const traffic = on && range !== 1 ? await trafficFor(ctx, settings, since, now) : [];
	const blocks = renderSecurity({
		state: loaded.state,
		source: settings.source,
		zone: settings.timeZone,
		range,
		days,
		traffic,
		metrics: metricsFor(loaded.metrics, settings, now),
		engineNames: settings.engineNames,
		metricsOn: on,
		now,
		lang,
	});
	return toast ? { blocks, toast } : { blocks };
}

/** A visit this long after the last one starts a new one, for "Since last visit". */
const VISIT_GAP_MS = 30 * 60_000;

/**
 * The Alerts explorer. Calls: kv.list and settings.list, then:
 *
 * - the visit's write, on a page load more than 30 minutes after the last;
 * - a write, when one was asked for: the explorer's ban, removal or delete,
 *   with the same checks and calls as on the CrowdSec decisions page;
 * - an alert's detail: the login and the GET;
 * - otherwise the day rows before the period and up to four log queries,
 *   with what is left.
 */
async function explorerPage(
	ctx: PluginContext,
	input: Record<string, unknown>,
	loaded: Loaded,
	result: SettingsResult,
	caller: Caller,
	now: Date,
	lang: Lang,
) {
	const settings = settingsOf(result);
	const zone = settings.timeZone;
	const parsed = parseExplorerInput(input);
	let view = parsed.view;
	const base = parsed.base;
	const mode = writeMode(settings, caller);
	let extra = 2;
	let toast: Toast | undefined;
	let review: WriteOutcome["review"];

	// "Since last visit": each viewer's visits, kept under the state's prefix.
	const userId = caller.user?.id;
	const visit = userId ? loaded.visits[userId] : undefined;
	const fresh = !visit || now.getTime() - Date.parse(visit.last) > VISIT_GAP_MS;
	const lastVisit = visit ? (fresh ? visit.last : (visit.previous ?? null)) : null;
	if (userId && fresh && input.type !== "block_action") {
		await ctx.kv.set(`${VISIT_PREFIX}${userId}`, { last: now.toISOString(), ...(visit && { previous: visit.last }) });
		extra++;
	}

	const source = result.ok ? buildSource(ctx, settings, loaded.state.skewMs) : null;
	const spent = () => extra + (source?.calls() ?? 0);
	const target = view.d ?? "";
	const ask: WriteAsk | null =
		base === X_BAN_REVIEW
			? { kind: "review", values: { ...asRecord(input.values), value: target } }
			: base === X_BAN_CONFIRM
				? { kind: "ban", values: asRecord(input.value) }
				: base === X_UNBAN
					? { kind: "unban", value: target }
					: base === X_DELETE
						? { kind: "delete", id: view.al }
						: null;
	if (ask) {
		const res = await runWrite(ctx, ask, settings, result, loaded, caller, source, () => BUDGET - spent(), now, lang);
		({ toast, review } = res);
		extra += res.extra;
		// After a change, the address's alerts.
		view = { ...view, n: 0 };
		delete view.al;
	}

	const range = rangeOf(view, now, zone, settings.retentionDays, lastVisit);
	let detail: { alert: RawAlert | null; error?: string } | undefined;
	if (view.al) {
		if (settings.source === "demo") detail = { alert: demoAlert(view.al, now) };
		else if (!result.ok) detail = { alert: null, error: problemText(lang, result.problem) };
		else if (!source?.lapi) detail = { alert: null, error: t(lang, "noNetwork") };
		else {
			const res = await source.lapi.alert(view.al);
			// A community blocklist alert is not this site's, and carries thousands of decisions: it is never listed.
			if (!res.ok) detail = { alert: null, error: problemText(lang, res.problem) };
			else detail = res.value && !isBlocklistAlert(res.value) ? { alert: res.value } : { alert: null, error: t(lang, "alertNotShown", { id: view.al }) };
		}
	}
	const data = view.al ? { period: [], seenBefore: new Set<string>(), partial: false, skipped: false } : await loadExplorer(ctx, range, zone, BUDGET - spent());
	const blocks = renderExplorer({
		view,
		range,
		data,
		retentionDays: settings.retentionDays,
		hasVisit: lastVisit !== null,
		zone,
		now,
		lang,
		writes: mode,
		engineNames: settings.engineNames,
		...(review && { review }),
		...(detail && { detail }),
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
	let review: WriteOutcome["review"];
	let wrote = false;
	// Calls the source does not count: a DNS lookup and a schedule.
	let extra = 0;
	const spentOn = () => 2 + (source?.calls() ?? 0) + extra;

	const ask: WriteAsk | null =
		base === BAN_REVIEW
			? { kind: "review", values: asRecord(input.values) }
			: base === BAN_CONFIRM
				? { kind: "ban", values: asRecord(input.value) }
				: base === DECISIONS_REMOVE
					? { kind: "decision", id: input.value }
					: null;
	if (ask) {
		const res = await runWrite(ctx, ask, settings, result, loaded, caller, source, () => BUDGET - spentOn(), now, lang);
		({ toast, review, wrote } = res);
		extra += res.extra;
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
