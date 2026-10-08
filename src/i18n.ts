/**
 * The plugin's own message catalogue.
 *
 * Block Kit plugins localise themselves: the host passes the
 * administrator's locale in `routeCtx.ui` and does not read plugin
 * catalogues. English is the source and the fallback. To add a language,
 * add a catalogue typed `Record<MessageKey, Message>` (so a missing entry
 * fails the build) and name it in `catalogues` and `langOf`. Manifest
 * strings (page labels, the widget title, the settings form) stay static.
 */

type Plural = { one: string; other: string };
type Message = string | Plural;

const en = {
	// Shared
	refresh: "Refresh",
	cancel: "Cancel",
	none: "None",
	noDataYet: "No security data yet",
	nothingRecorded: "Nothing recorded yet.",
	rangeDays: { one: "{count} day", other: "{count} days" },
	hours: { one: "{count} hour", other: "{count} hours" },
	minutes: { one: "{count} minute", other: "{count} minutes" },
	showingRows: "Rows {from} to {to}.",
	openSecurity: "Open security",
	securityPage: "Security",
	alertsPage: "Alerts",
	decisionsPage: "Decisions",
	checkSetup: "Check setup",

	// Kinds
	kindWaf: "WAF",
	kindBot: "Bot challenge",
	kindBehaviour: "Behaviour",
	kindManual: "Manual",

	// Widget and Security page
	alerts24h: "Alerts, last 24 hours",
	activeBans: "Active bans",
	asOf: "as of {age}",
	notCountedYet: "not counted yet",
	colTopScenarios: "Top scenarios, 24 hours",
	colAlerts: "Alerts",
	alertsInRange: "Alerts, last {days} days",
	bansInRange: "Bans issued, last {days} days",
	wafInRange: "WAF blocks, last {days} days",
	alertsByDay: "Alerts by day",
	bansByDay: "Bans issued by day",
	bansIssued: "Bans issued",
	historyStarts: "Stored history starts on {date}",
	topScenarios: "Top scenarios",
	topSources: "Most active sources",
	topCountries: "Top countries",
	topAsNames: "Top AS organisations",
	topPaths: "Most targeted paths",
	topListsNote:
		"Top lists add up each day's 25 most frequent values, so a value that never made a day's top 25 is undercounted. Days run in the time zone set in the plugin's settings ({zone}).",
	colScenario: "Scenario",
	colAddress: "Address",
	colCountry: "Country",
	colAsName: "AS organisation",
	colPath: "Path",

	// Freshness
	demoData: "Demo data, not real alerts",
	synced: "Synced {age}",
	notSynced: "Not synced yet",
	historyReading: "Still reading history before {time}",
	lastAttemptFailed: "Last attempt failed: {error}",
	lastAttemptFailedAge: "Last attempt failed {age}: {error}",
	firstSyncPending: "The first sync has not run yet. It is scheduled, and the numbers appear once it has.",
	syncedNoAlerts: "Synced, and CrowdSec reported no alerts in the stored time.",
	noEarlierPeriod: "no earlier period to compare yet",
	noneEitherPeriod: "none in either period",
	upFromNone: "up from none in the period before",
	vsPrevious: "{change} vs the period before",
	syncRequested: "Sync requested. The numbers update with the next scheduled run.",
	syncUnschedulable: "This site runs no scheduled tasks, so no sync can be requested.",

	// Alerts page
	allKinds: "All kinds",
	allScenarios: "All scenarios",
	allAlerts: "All stored alerts, newest first.",
	filteredBy: "Stored alerts for {filters}, newest first.",
	colTime: "Time",
	colKind: "Kind",
	colDecision: "Decision",
	noAlertsHere: "No stored alerts match.",
	delete: "Delete",
	deleteAlertTitle: "Delete this alert?",
	deleteAlertText:
		"Alert {id} ({scenario} from {ip}) is deleted from CrowdSec. This cannot be undone. Its decisions ended more than two minutes ago.",
	deleteNote:
		"Delete shows only on alerts whose decisions ended more than two minutes ago. Deleting an alert deletes its decisions where bouncers never hear of it, so a ban is lifted with Remove on the Decisions page instead.",

	// Decisions page
	colType: "Type",
	colOrigin: "Origin",
	colRemaining: "Remaining",
	decisionsCount: {
		one: "{count} active decision, {bans} banned addresses.",
		other: "{count} active decisions, {bans} banned addresses.",
	},
	decisionsTruncated: "Read from the newest {count} alerts with an active decision, so there may be more.",
	decisionsNotRead: "List not read this time",
	decisionsNotReadDetail: "The change used this request's share of calls. Press Refresh to read the list.",
	noActiveDecisions: "No active decisions.",
	remove: "Remove",
	removeTitle: "Remove this decision?",
	removeText: "The {type} on {value} is removed. Bouncers drop it on their next poll.",
	remainingDays: "{days} d {hours} h",
	remainingHours: "{hours} h {minutes} min",
	remainingMinutes: "{minutes} min",
	remainingSeconds: "{seconds} s",
	banTitle: "Ban an address",
	protectedCaller: "Your address",
	protectedSite: "This site",
	protectedLapi: "CrowdSec LAPI host",
	protectedSetting: "Protected addresses setting",
	callerUnknown: "Not found in this request, so a ban cannot be checked against it",
	notLookedUp: "Not looked up yet. Review a ban or run the setup check to look it up.",
	protectedBuiltIn:
		"A ban also never covers private, loopback, link-local, CGNAT (including Tailscale's 100.64.0.0/10), multicast or unspecified space, a range wider than /16 for IPv4 or /48 for IPv6, or an address on a CrowdSec allowlist. Mapped, NAT64 and 6to4 IPv6 addresses are checked as the IPv4 address they carry.",
	protectedInvalid: "These protected address entries are not addresses and protect nothing: {entries}.",
	fieldAddress: "Address or range",
	fieldDuration: "Duration",
	fieldType: "Type",
	fieldNote: "Note",
	fieldNoteHint: "Why, recorded with the decision",
	duration_1h: "1 hour",
	duration_4h: "4 hours",
	duration_24h: "24 hours",
	duration_7d: "7 days",
	duration_30d: "30 days",
	typeBan: "Ban",
	typeCaptcha: "Captcha",
	reviewBan: "Review ban",
	reviewTitle: "Ready to ban",
	reviewWhat: "{type} {value} for {duration}.",
	reviewChecks: "Every protection passed, the CrowdSec allowlist included. Ban runs them all again before it adds the decision.",
	ownChecked: "It is not your own address.",
	ownNotChecked: "Could not confirm this is not your own address: this request carried none.",
	banNow: "Ban",
	banConfirmTitle: "Add this decision?",

	// Setup check
	setupTitle: "Setup check",
	setupAllGood: "Everything the numbers depend on is in place.",
	setupProblems: {
		one: "{count} problem stops or distorts the numbers.",
		other: "{count} problems stop or distort the numbers.",
	},
	backToSecurity: "Back to security",
	checkAgain: "Check again",
	colCheck: "Check",
	colStatus: "Status",
	colDetails: "Details",
	statusOk: "OK",
	statusProblem: "Problem",
	statusWaiting: "Waiting",
	statusSkipped: "Not checked",
	checkSource: "Data source",
	checkSettings: "Settings",
	checkTimeZone: "Time zone",
	checkUrl: "LAPI URL",
	checkLogin: "Login",
	checkUserAgent: "User-Agent",
	checkRead: "Read access",
	checkChanges: "Changes",
	checkProtections: "Ban protections",
	checkScheduler: "Scheduled sync",
	checkLastSync: "Last sync",
	sourceDemo: "Demo data: generated alerts. No LAPI is asked anything.",
	sourceLapi: "CrowdSec Local API.",
	settingsSaved: "Saved.",
	encryptionHint:
		"The password is saved encrypted with EMDASH_ENCRYPTION_KEY, and EmDash refuses to save it without that key: run npx emdash secrets generate and set it on the site.",
	needsSettings: "Needs the settings above.",
	needsUrl: "Needs a usable LAPI URL.",
	needsLogin: "Needs a working login.",
	urlInvalid:
		"The LAPI URL {url} is not a usable address. It is the LAPI's base on HTTPS, without a query, for example https://www.example.com/crowdsec-lapi.",
	urlPrivate:
		"{url} is a private or internal address, and EmDash refuses to fetch those. Publish the LAPI on a public HTTPS hostname behind a proxy that admits only this site.",
	urlNotHttps: "The LAPI URL {url} is plain HTTP, and the plugin only uses HTTPS: the machine password and the token would cross the internet readable.",
	timeZoneInvalid:
		"The Time zone setting, {zone}, is not a time zone this server knows. The sync waits until it is an IANA name such as Australia/Sydney, so no stored day is counted again in another zone.",
	localSiteName:
		"Bans are refused: {name} is a local name, which cannot be looked up to protect the site's own addresses. Set the site URL and the LAPI URL to public hostnames.",
	urlUserinfo:
		"The LAPI URL has a user name or password in it. Remove it: the machine ID and password have their own settings, and a URL carrying credentials is never used.",
	loginOk: "Logged in as {machine}.",
	userAgentOk: "Sent as {ua}, which LAPI accepts.",
	userAgentMaybe:
		"The plugin sends User-Agent {ua}. LAPI refuses a login whose User-Agent is not name/version, so a proxy that replaces the User-Agent causes the refusal above as surely as a wrong password does.",
	readOk: "GET /v1/alerts answers.",
	changesOffDetail: "Off: the plugin only reads.",
	changesOnDetail: "On: administrators can ban, remove decisions and delete alerts.",
	protectionsLiteral: "The site and the LAPI are addresses, so no lookup is needed.",
	protectionsOk: {
		one: "Protected: {site}, {lapi}, and {count} protected address entry.",
		other: "Protected: {site}, {lapi}, and {count} protected address entries.",
	},
	schedulerNotScheduled: "The sync is not scheduled yet. Opening the dashboard schedules it.",
	schedulerWaiting: "Scheduled every {interval}, not run yet. If it still has not run after {interval}, the site runs no scheduled tasks.",
	schedulerOk: "Last run {age}, scheduled every {interval}.",
	schedulerStale: "Last run {age}, but scheduled every {interval}: the site's scheduler is not running on time.",
	schedulerNeverRan: "Scheduled {age} to run every {interval}, and it has never run: the site's scheduler is not running.",
	schedulerRefreshStuck: "A requested sync was due {age} and has not run: the site's scheduler is not running.",
	schedulerHowTo:
		"On Cloudflare Workers, scheduled tasks need a Cron Trigger on the Worker, added to wrangler.jsonc and deployed. EmDash's deployment guide has the scheduled handler that goes with it.",

	// Problems: each one sentence naming the fix
	notConfigured: "CrowdSec is not configured yet: add {parts} in the plugin's settings.",
	part_lapiUrl: "the LAPI URL",
	part_machineId: "the machine ID",
	part_machinePassword: "the machine password",
	noNetwork: "The plugin cannot make network requests: its network permission is not granted.",
	storageUnavailable: "The plugin's storage collections are not available.",
	loginRefused:
		"LAPI refused the login (401). Check the machine ID and password, and that no proxy replaces the User-Agent: LAPI refuses one that is not name/version.",
	tokenRefused: "LAPI refused the session token twice in a row. Check that the machine still exists (cscli machines list).",
	routeRefused:
		"The proxy in front of LAPI refused {route} (403). Admit that route for this site's address, as the README shows.",
	routeMissing: "LAPI has no {route} at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	notLapi: "There is no LAPI login at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	notJson: "The LAPI URL answered with a web page instead of JSON (HTTP {status}): a sign-in page or another site is in front of it.",
	unexpectedAnswer: "LAPI answered in a form this plugin does not know.",
	rateLimited: "LAPI or its proxy limited the request rate (429). The next sync tries again.",
	httpStatus: "LAPI answered HTTP {status}.",
	lapiSaid: "LAPI answered HTTP {status}: {message}",
	unreachable: "LAPI could not be reached: {detail}",
	blockedHost: "EmDash refused to fetch the LAPI URL because it points at a private or internal address: {detail}",
	tooLarge: "LAPI's answer was over the 8 MiB a plugin may receive. The next try asks for fewer alerts.",
	redirected:
		"The LAPI URL answered with a redirect (HTTP {status}), which the plugin does not follow, so the password is never sent to another address. Set the LAPI URL to the address the redirect points at.",
	allowlistUnreadable:
		"LAPI's allowlist check answered in a form the plugin cannot read, so the ban was not added. Check that the proxy admits POST /v1/allowlists/check.",
	dnsFailed: "Looking up {name} for the ban protections failed: {detail}",
	dnsEmpty: "{name} has no address, so a ban cannot be checked against it. Check the site URL and the LAPI URL.",
	dnsJustLoaded: "The site's and the LAPI's addresses were just looked up for the ban protections. Try again.",

	// Write refusals and results
	changesOff: "Changes are off. An administrator can turn on Allow changes in the plugin's settings.",
	demoNoChanges: "Demo data cannot be changed. Changes need a CrowdSec LAPI.",
	adminOnly: "Only an administrator can change CrowdSec.",
	invalidAddress: "That is not an IPv4 or IPv6 address or a CIDR range.",
	invalidDuration: "Pick a duration from the list: 1h, 4h, 24h, 7d or 30d.",
	invalidType: "The type is ban or captcha.",
	invalidId: "That is not an id.",
	rangeTooWide: "Refused: the range is wider than {widest}, the widest a ban may cover.",
	reservedAddress:
		"Refused: the address is in private, loopback, link-local, CGNAT, multicast or reserved space, which is never banned.",
	ownAddress: "Refused: it covers your own address ({match}).",
	mcpClientAddress: "Refused: it covers the address this MCP client connects from ({match}).",
	hostBits: "That range has bits set after its prefix. Write it as {meant}.",
	protectedInvalidRefuse:
		"Changes are refused until the Protected addresses setting is fixed: {entries} cannot be read. Only IP addresses and CIDR ranges are accepted there, not hostnames.",
	siteAddress: "Refused: it covers this site's address ({match}).",
	lapiAddress: "Refused: it covers the CrowdSec LAPI host's address ({match}).",
	settingAddress: "Refused: it covers {match} from the Protected addresses setting.",
	allowlisted: "Refused: the address is on a CrowdSec allowlist.",
	allowlistedReason: "Refused: the address is on a CrowdSec allowlist ({reason}).",
	banDone: "Added: {type} on {value} for {duration}. Bouncers apply it on their next poll.",
	banDoneUnchecked:
		"Added: {type} on {value} for {duration}. Could not confirm this is not your own address: the request carried none.",
	banDoneUncheckedMcp:
		"Added: {type} on {value} for {duration}. Could not check it against the address this MCP client connects from: the request carried none.",
	decisionRemoved: "Removed decision {id}. Bouncers drop it on their next poll.",
	decisionGone: "That decision is already gone.",
	noActiveBan: "No active decision is on exactly {value}.",
	removedAll: { one: "Removed {count} decision on {value}.", other: "Removed {count} decisions on {value}." },
	removedSome: "Removed {count} decisions on {value}. {remaining} remain: run it again.",
	alertGone: "Alert {id} is not in CrowdSec any more, so it was taken off the list.",
	alertHasActiveDecision:
		"Refused: alert {id} still has an active decision. Remove the decision on the Decisions page first, then delete the alert two minutes later.",
	alertDecisionJustEnded:
		"Refused: a decision of alert {id} ended less than two minutes ago, and bouncers may not have heard yet. Try again in two minutes.",
	alertDeleted: "Deleted alert {id}.",
	alertDecisionUnknown:
		"Refused: a decision of alert {id} has an end time the plugin cannot read, so it may still be in force. Remove the decision on the Decisions page first.",
	tryAgain: "The login used this request's share of calls. Try again.",
} satisfies Record<string, Message>;

export type MessageKey = keyof typeof en;

const catalogues = { en } as const;

export type Lang = keyof typeof catalogues;
export type Params = Record<string, string | number>;

/** A translatable failure, stored so the text follows the reader's language. */
export interface Problem {
	key: MessageKey;
	params?: Params;
}

/** The catalogue for an admin locale. English until another catalogue is added. */
export function langOf(locale: string | undefined): Lang {
	const base = locale?.toLowerCase().split(/[-_]/)[0];
	return base && base in catalogues ? (base as Lang) : "en";
}

export function t(lang: Lang, key: MessageKey, params: Params = {}): string {
	const message: Message = catalogues[lang][key];
	const template =
		typeof message === "string"
			? message
			: new Intl.PluralRules(lang).select(Number(params.count ?? 0)) === "one"
				? message.one
				: message.other;
	return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in params ? String(params[name]) : match));
}

/** A problem in the reader's language. */
export function problemText(lang: Lang, problem: Problem): string {
	if (problem.key === "notConfigured") {
		const missing = String(problem.params?.missing ?? "")
			.split(",")
			.filter(Boolean);
		const parts = missing.map((key) => {
			const part = `part_${key}`;
			return part in catalogues[lang] ? t(lang, part as MessageKey) : key;
		});
		return t(lang, "notConfigured", { parts: listOf(lang, parts) });
	}
	return t(lang, problem.key, problem.params);
}

function listOf(lang: Lang, parts: string[]): string {
	try {
		return new Intl.ListFormat(lang, { type: "conjunction" }).format(parts);
	} catch {
		return parts.join(", ");
	}
}

/** A failed `Result`, with the English text for logs and the key for each reader's language. */
export function failure(key: MessageKey, params?: Params): { ok: false; error: string; problem: Problem } {
	return { ok: false, error: t("en", key, params), problem: { key, ...(params && { params }) } };
}
