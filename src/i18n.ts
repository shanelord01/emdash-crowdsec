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
	openSecurity: "Open CrowdSec",
	securityPage: "CrowdSec",
	alertsPage: "CrowdSec alerts",
	decisionsPage: "CrowdSec decisions",
	checkSetup: "Check setup",

	// Kinds
	kindWaf: "WAF",
	kindBot: "Bot challenge",
	kindBehaviour: "Behaviour",
	kindManual: "Manual",

	// Widget and the CrowdSec page
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
	topScenarios: "Top scenarios",
	topSources: "Most active sources",
	topCountries: "Top countries",
	topAsNames: "Top AS organisations",
	topPaths: "Most targeted paths",
	topListsNote:
		"Top lists add up each day's 25 most frequent values, so a value that never made a day's top 25 is undercounted. Days run in the time zone set in the plugin's settings ({zone}).",
	topListsTwoDays: "In the 24-hour view they cover today and yesterday.",
	colScenario: "Scenario",
	colAddress: "Address",
	colCountry: "Country",
	colAsName: "AS organisation",
	colNetwork: "Network",
	colPath: "Path",

	// Freshness
	demoData: "Demo data, not real alerts",
	synced: "Synced {age}",
	notSynced: "Not synced yet",
	historyReading: "Still reading history before {time}",
	lastAttemptFailed: "Last attempt failed: {error}",
	lastAttemptFailedAge: "Last attempt failed {age}: {error}",
	firstSyncPending: "The first sync has not run yet. It is scheduled, and the numbers follow.",
	syncedNoAlerts: "Synced, and CrowdSec reported no alerts in the stored time.",
	noEarlierPeriod: "no earlier period to compare yet",
	noneEitherPeriod: "none in either period",
	upFromNone: "up from none in the period before",
	vsPrevious: "{change} vs the period before",
	syncRequested: "Sync requested. The numbers update with the next scheduled run.",
	syncUnschedulable: "This site runs no scheduled tasks, so no sync can be requested.",

	// Ranges and charts
	range24h: "24 hours",
	alertsByHour: "Alerts by hour",
	bansByHour: "Bans issued by hour",
	bans24h: "Bans issued, last 24 hours",
	waf24h: "WAF blocks, last 24 hours",
	whereFrom: "Where attacks come from",
	alertsByCountry: "alerts by country, the ten with most",
	colourBlue: "Blue",
	colourYellow: "Yellow",
	colourPink: "Pink",
	colourPurple: "Purple",
	colourTeal: "Teal",
	colourOrange: "Orange",

	// Traffic
	originCommunity: "Community blocklist",
	originDetections: "Your detections",
	originManual: "Manual",
	originOther: "Other",
	trafficDiscarded: "Malicious traffic discarded",
	trafficWaiting: "The first metrics sample sets the baseline. Traffic appears after the next sync.",
	packetsDiscarded: "Packets discarded",
	shareDiscarded: "Share of traffic discarded",
	shareOf: "{share} of {processed} packets the firewall bouncer checked",
	webRequests: "Web requests",
	requestsInspected: "Requests inspected by AppSec",
	requestsBlocked: "Requests blocked",
	challengeFunnel: "Bot challenge",
	challenges: "Challenges",
	challenge_requested: "Requested",
	challenge_submitted: "Submitted",
	challenge_accepted: "Accepted",
	challenge_rejected: "Rejected",
	challenge_exempt: "Exempt",
	challengesDay: "bot challenges at each stage, last 24 hours",
	challengesRange: "bot challenges at each stage, last {days} days",
	bansBySource: "Active bans by source",
	activeDecisions: "Active decisions",
	activeDecisionsNow: "active decisions now, by source",
	colCommunityReason: "Community blocklist reason",
	colDecisions: "Decisions",
	trafficNote: "From the security engine's and the firewall bouncer's own metrics, sampled with each sync since {age}.",
	discardedWeek: "Discarded this week",
	packetsShort: "{count} packets",

	// Alerts explorer
	allKinds: "All kinds",
	colKind: "Kind",
	colDecision: "Decision",
	noAlertsHere: "No stored alerts match.",
	period1h: "1 hour",
	period24h: "24 hours",
	period3d: "3 days",
	period7d: "7 days",
	period30d: "30 days",
	periodRet: "Everything kept",
	periodRetDays: "{days} days (all kept)",
	periodVisit: "Since last visit",
	periodRange: "{from} to {to}",
	dimIp: "Source IP",
	dimBehaviour: "Behaviour",
	dimPath: "Target path",
	dimEngine: "Engine",
	alertsByEngine: "Alerts by engine",
	alertsByEngineLine: "alerts by the CrowdSec agent that raised them",
	seenByEngines: { one: "seen by {count} engine", other: "seen by {count} engines" },
	bhExploit: "HTTP exploit",
	bhScan: "HTTP scan",
	bhCrawl: "HTTP crawl",
	bhBot: "Bot",
	bhSsh: "SSH brute force",
	bhManual: "Manual",
	bhGeneric: "Generic",
	any: "Any",
	unknown: "Unknown",
	other: "Other",
	filterIp: "IP address or CIDR range",
	applyFilters: "Apply filters",
	filterBy: "Filter",
	changeBreakdown: "Change breakdown",
	colShare: "Share",
	colWhen: "When",
	colSource: "Source",
	colTarget: "Target",
	colKey: "Key",
	colValue: "Value",
	colUserAgent: "User agent",
	colRule: "Rule",
	explorerCount: { one: "{formatted} alert matches.", other: "{formatted} alerts match." },
	explorerPartial: "This period holds more stored alerts than a page reads, so the oldest are left out. Pick a shorter one.",
	explorerNotRead: "Alerts not read this time",
	groupByIp: "Group by IP",
	eachAlert: "Show each alert",
	groupsCount: { one: "{count} address. Rows {from} to {to}.", other: "{count} addresses. Rows {from} to {to}." },
	alertsOver: { one: "{count} alert", other: "{count} alerts over {span}" },
	spanUnderMinute: "under a minute",
	firstSeen: "first {time}",
	firstSeenLabel: "First seen",
	detectWaf: "WAF",
	detectLog: "Log",
	detectBoth: "WAF and log",
	decisionsN: { one: "{count} decision", other: "{count} decisions" },
	decisionEnded: "{type}, ended",
	plusMore: "+{count} more",
	viewAlerts: "View alerts",
	alertDetail: "Alert detail",
	hintBanned: "Banned now",
	hintSeenBefore: "Seen before",
	hints: "Hints",
	backToExplorer: "All addresses",
	backToAlerts: "Back",
	alertsFrom: "Alerts from {ip}",
	decisionsActive: "Active decision",
	bannedFor: "{remaining} left",
	alertTitle: "Alert {id}: {scenario}",
	started: "Started",
	eventsCount: "Events",
	message: "Message",
	alertMeta: "Meta",
	alertEvents: "Events ({count} of {total})",
	ended: "Ended",
	noDecisionsOnAlert: "No decisions on this alert.",
	andMore: "And {count} more.",
	alertNotShown: "Alert {id} is not one of this site's alerts in CrowdSec.",
	removeBan: "Remove ban",
	removeBanText: "Every active decision on exactly {value} is removed. Bouncers drop them on their next poll.",
	reviewBanOf: "Review a ban of {value}",
	demoWrites: "Demo data: these controls run their checks and change nothing.",
	delete: "Delete",
	deleteAlertTitle: "Delete this alert?",
	deleteAlertText: "Alert {id} ({scenario} from {ip}) is deleted from CrowdSec. This cannot be undone.",
	deleteNote: "Delete shows once an alert's decisions ended over two minutes ago: deleting an alert deletes its decisions where bouncers never hear of it. Lift a ban with Remove ban instead.",

	// Decisions page
	colType: "Type",
	colOrigin: "Origin",
	colRemaining: "Remaining",
	decisionsCount: {
		one: "{count} active decision, {bans} banned addresses.",
		other: "{count} active decisions, {bans} banned addresses.",
	},
	decisionsTruncated: "Read from the newest {count} alerts with an active decision: there may be more.",
	decisionsNotRead: "List not read this time",
	decisionsNotReadDetail: "The change used this request's share of calls. Read the page again to see it.",
	noActiveDecisions: "No active decisions.",
	blocklistCount: {
		one: "Also enforcing {formatted} address from the CrowdSec community blocklist and lists, as of {age}. They are counted, not listed.",
		other: "Also enforcing {formatted} addresses from the CrowdSec community blocklist and lists, as of {age}. They are counted, not listed.",
	},
	blocklistTooMany: "Also enforcing the CrowdSec community blocklist: too many addresses to count, as of {age}.",
	alreadyBlocklisted: "The CrowdSec community blocklist already blocks it.",
	onlyBlocklisted: "{value} is blocked only by the CrowdSec community blocklist or a list, which CrowdSec would add back. To let it through, add it to a CrowdSec allowlist.",
	remove: "Remove",
	removeTitle: "Remove this decision?",
	removeText: "The {type} on {value} is removed. Bouncers drop it on their next poll.",
	remainingDays: "{days} d {hours} h",
	remainingHours: "{hours} h {minutes} min",
	remainingMinutes: "{minutes} min",
	remainingSeconds: "{seconds} s",
	banTitle: "Ban an address in CrowdSec",
	protectedCaller: "Your address",
	protectedSite: "This site",
	protectedLapi: "CrowdSec LAPI host",
	protectedSetting: "Protected addresses setting",
	callerUnknown: "Not in this request, so a ban cannot be checked against it",
	notLookedUp: "Not looked up yet. A ban review or the setup check looks it up.",
	protectedBuiltIn: "A ban never covers private, loopback, link-local, CGNAT (Tailscale's 100.64.0.0/10 too), multicast or unspecified space, a range wider than /16 or /48, or a CrowdSec allowlist entry. IPv6 that carries IPv4 is checked as that IPv4 address.",
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
	reviewChecks: "Every protection passed, the CrowdSec allowlist included. Ban runs them all again.",
	ownChecked: "It is not your own address.",
	ownNotChecked: "Could not confirm this is not your own address: this request carried none.",
	banNow: "Ban",
	banConfirmTitle: "Add this decision?",

	// Setup check
	setupTitle: "CrowdSec setup check",
	setupAllGood: "Everything the numbers depend on is in place.",
	setupProblems: {
		one: "{count} problem stops or distorts the numbers.",
		other: "{count} problems stop or distort the numbers.",
	},
	backToSecurity: "Back to CrowdSec",
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
	checkEngineMetrics: "Engine metrics",
	checkFirewallMetrics: "Firewall metrics",
	metricsOff: "Not set: its traffic charts are off.",
	metricsOk: "Answers, {count} series read: {names}.",
	metricsNone: "Answers, but none of the series the charts read: {expected}.",
	metricsDeferred: "Not checked: the DNS lookup used this check's calls. Press Check again.",
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
	encryptionHint: "The password is saved encrypted with EMDASH_ENCRYPTION_KEY: run npx emdash secrets generate and set it on the site.",
	needsSettings: "Needs the settings above.",
	needsUrl: "Needs a usable LAPI URL.",
	needsLogin: "Needs a working login.",
	urlInvalid: "{url} is not a usable LAPI URL. It is LAPI's HTTPS base, for example https://www.example.com/crowdsec-lapi.",
	urlPrivate: "{url} is a private or internal address, which EmDash refuses to fetch. Publish LAPI on a public HTTPS hostname, as the README shows.",
	urlNotHttps: "The LAPI URL {url} is plain HTTP, and the plugin only uses HTTPS: the machine password and the token would cross the internet readable.",
	timeZoneInvalid: "The Time zone setting, {zone}, is not one this server knows. The sync waits for an IANA name such as Australia/Sydney.",
	localSiteName: "Bans are refused: {name} is a local name, which cannot be looked up to protect the site. Use public hostnames for the site and the LAPI.",
	urlUserinfo: "The LAPI URL has a user name or password in it, so it is never used. Remove it: the machine ID and password have their own settings.",
	loginOk: "Logged in as {machine}.",
	userAgentOk: "Sent as {ua}, which LAPI accepts.",
	userAgentMaybe: "Sent as {ua}. LAPI refuses a login whose User-Agent is not name/version, so a proxy that replaces it causes the refusal above.",
	readOk: "GET /v1/alerts answers.",
	changesOffDetail: "Off: the plugin only reads.",
	changesOnDetail: "On: administrators can ban, remove decisions and delete alerts.",
	protectionsLiteral: "The site and the LAPI are addresses, so no lookup is needed.",
	protectionsOk: {
		one: "Protected: {site}, {lapi}, and {count} protected address entry.",
		other: "Protected: {site}, {lapi}, and {count} protected address entries.",
	},
	schedulerNotScheduled: "The sync is not scheduled yet. Opening the dashboard schedules it.",
	schedulerWaiting: "Scheduled every {interval}, not run yet. If it has not run after {interval}, the site runs no scheduled tasks.",
	schedulerOk: "Last run {age}, scheduled every {interval}.",
	schedulerStale: "Last run {age}, but scheduled every {interval}: the site's scheduler is not running on time.",
	schedulerNeverRan: "Scheduled {age} to run every {interval}, and never run: the site's scheduler is not running.",
	schedulerRefreshStuck: "A requested sync was due {age} and has not run: the site's scheduler is not running.",
	schedulerHowTo: "On Cloudflare Workers, scheduled tasks need a Cron Trigger in wrangler.jsonc and the scheduled handler from EmDash's deployment guide.",

	// Problems: each one sentence naming the fix
	notConfigured: "CrowdSec is not configured yet: add {parts} in the plugin's settings.",
	part_lapiUrl: "the LAPI URL",
	part_machineId: "the machine ID",
	part_machinePassword: "the machine password",
	noNetwork: "The plugin cannot make network requests: its network permission is not granted.",
	storageUnavailable: "The plugin's storage collections are not available.",
	loginRefused: "LAPI refused the login (401). Check the machine ID and password, and that no proxy replaces the User-Agent.",
	tokenRefused: "LAPI refused the session token twice. Check that the machine still exists (cscli machines list).",
	routeRefused: "The proxy refused {route} (403). Admit it for this site's address, as the README shows.",
	routeMissing: "LAPI has no {route} at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	notLapi: "There is no LAPI login at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	notJson: "The LAPI URL answered with a web page, not JSON (HTTP {status}): a sign-in page or another site is in front of it.",
	unexpectedAnswer: "LAPI answered in a form this plugin does not know.",
	rateLimited: "LAPI or its proxy limited the request rate (429). The next sync tries again.",
	httpStatus: "LAPI answered HTTP {status}.",
	lapiSaid: "LAPI answered HTTP {status}: {message}",
	unreachable: "LAPI could not be reached: {detail}",
	blockedHost: "EmDash refused the LAPI URL as a private or internal address: {detail}",
	tooLarge: "LAPI's answer was over the 8 MiB a plugin may receive. The next try asks for fewer.",
	redirected: "The LAPI URL answered with a redirect (HTTP {status}). The plugin follows none, so the password never goes elsewhere: set the URL the redirect points at.",
	allowlistUnreadable: "The ban was not added: LAPI's allowlist check answered in a form the plugin cannot read. Check that the proxy admits POST /v1/allowlists/check.",
	metricsUnreachable: "The metrics URL could not be reached: {detail}",
	metricsRefused: "The proxy refused the metrics URL (403). Admit GET on it for this site's address.",
	metricsHttp: "The metrics URL answered HTTP {status}.",
	metricsNotPrometheus: "The metrics URL answered with a web page instead of Prometheus metrics: a sign-in or challenge page is in front of it.",
	dnsFailed: "Looking up {name} for the ban protections failed: {detail}",
	dnsEmpty: "{name} has no address, so a ban cannot be checked against it. Check the site URL and the LAPI URL.",
	dnsJustLoaded: "The site's and the LAPI's addresses were just looked up for the ban protections. Try again.",

	// Write refusals and results
	changesOff: "Changes are off. An administrator can turn on Allow changes in the plugin's settings.",
	demoNoChanges: "Demo data cannot be changed. Changes need a CrowdSec LAPI.",
	demoNothingChanged: "Demo data: nothing was changed.",
	adminOnly: "Only an administrator can change CrowdSec.",
	invalidAddress: "That is not an IPv4 or IPv6 address or a CIDR range.",
	invalidDuration: "Pick a duration from the list: 1h, 4h, 24h, 7d or 30d.",
	invalidType: "The type is ban or captcha.",
	invalidId: "That is not an id.",
	rangeTooWide: "Refused: the range is wider than {widest}, the widest a ban may cover.",
	reservedAddress: "Refused: private, loopback, link-local, CGNAT, multicast and reserved space is never banned.",
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
	banDoneUnchecked: "Added: {type} on {value} for {duration}. Could not confirm this is not your own address: the request carried none.",
	banDoneUncheckedMcp:
		"Added: {type} on {value} for {duration}. Could not check it against the address this MCP client connects from: the request carried none.",
	decisionRemoved: "Removed decision {id}. Bouncers drop it on their next poll.",
	decisionGone: "That decision is already gone.",
	noActiveBan: "No active decision is on exactly {value}.",
	removedAll: { one: "Removed {count} decision on {value}.", other: "Removed {count} decisions on {value}." },
	removedSome: "Removed {count} decisions on {value}. {remaining} remain: run it again.",
	alertGone: "Alert {id} is not in CrowdSec any more, so it was taken off the list.",
	alertHasActiveDecision: "Refused: alert {id} still has an active decision. Remove it first, then delete the alert two minutes later.",
	alertDecisionJustEnded:
		"Refused: a decision of alert {id} ended less than two minutes ago, and bouncers may not have heard yet. Try again in two minutes.",
	alertDeleted: "Deleted alert {id}.",
	alertDecisionUnknown: "Refused: a decision of alert {id} has an end time the plugin cannot read, so it may still be in force. Remove the decision first.",
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
