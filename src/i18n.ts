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

/*
 * Keys are short codes (`m0`, `m1`, ...) to keep the runtime bundle small:
 * every key is in it twice, once here and once where it is used, and the
 * registry caps the bundle at 128 KB. The comment above each entry is its
 * name. Keys with an underscore (`duration_4h`, `challenge_requested`,
 * `part_lapiUrl`) and one-word keys keep their names, since some are built
 * from a prefix at run time. To find a message, search for its name here.
 */
const en = {
	// Shared
	refresh: "Refresh",
	cancel: "Cancel",
	none: "None",
	// noDataYet
	m0: "No security data yet",
	// nothingRecorded
	m1: "Nothing recorded yet.",
	// rangeDays
	m2: { one: "{count} day", other: "{count} days" },
	hours: { one: "{count} hour", other: "{count} hours" },
	minutes: { one: "{count} minute", other: "{count} minutes" },
	// showingRows
	m3: "Rows {from} to {to}.",
	// openSecurity
	m4: "Open CrowdSec",
	// securityPage
	m5: "CrowdSec",
	// alertsPage
	m6: "CrowdSec alerts",
	// decisionsPage
	m7: "CrowdSec decisions",
	// checkSetup
	m8: "Check setup",

	// Kinds
	// kindWaf
	m9: "WAF",
	// kindBot
	ma: "Bot challenge",
	// kindBehaviour
	mb: "Behaviour",
	// kindManual
	mc: "Manual",

	// Widget and the CrowdSec page
	alerts24h: "Alerts, last 24 hours",
	// activeBans
	md: "Active bans",
	// asOf
	me: "as of {age}",
	// notCountedYet
	mf: "not counted yet",
	// colTopScenarios
	mg: "Top scenarios, 24 hours",
	// colAlerts
	mh: "Alerts",
	// alertsInRange
	mi: "Alerts, last {days} days",
	// bansInRange
	mj: "Bans issued, last {days} days",
	// wafInRange
	mk: "WAF blocks, last {days} days",
	// alertsByDay
	ml: "Alerts by day",
	// bansByDay
	mm: "Bans issued by day",
	// bansIssued
	mn: "Bans issued",
	// topScenarios
	mo: "Top scenarios",
	// topSources
	mp: "Most active sources",
	// topCountries
	mq: "Top countries",
	// topAsNames
	mr: "Top AS organisations",
	// topPaths
	ms: "Most targeted paths",
	// topListsNote
	mt:
		"Top lists add up each day's 25 most frequent values, so a value that never made a day's top 25 is undercounted. Days run in the time zone set in the plugin's settings ({zone}).",
	// topListsTwoDays
	mu: "In the 24-hour view they cover today and yesterday.",
	// colScenario
	mv: "Scenario",
	// colAddress
	mw: "Address",
	// colCountry
	mx: "Country",
	// colAsName
	my: "AS organisation",
	// colNetwork
	mz: "Network",
	// colPath
	m10: "Path",

	// Freshness
	synced: "Synced {age}",
	// notSynced
	m11: "Not synced yet",
	// historyReading
	m12: "Still reading history before {time}",
	// lastAttemptFailed
	m13: "Last attempt failed: {error}",
	// lastAttemptFailedAge
	m14: "Last attempt failed {age}: {error}",
	// firstSyncPending
	m15: "The first sync has not run yet. It is scheduled, and the numbers follow.",
	// syncedNoAlerts
	m16: "Synced, and CrowdSec reported no alerts in the stored time.",
	// noEarlierPeriod
	m17: "no earlier period to compare yet",
	// noneEitherPeriod
	m18: "none in either period",
	// upFromNone
	m19: "up from none in the period before",
	// vsPrevious
	m1a: "{change} vs the period before",
	// syncRequested
	m1b: "Sync requested. The numbers update with the next scheduled run.",
	// syncUnschedulable
	m1c: "This site runs no scheduled tasks, so no sync can be requested.",

	// Ranges and charts
	range24h: "24 hours",
	// alertsByHour
	m1d: "Alerts by hour",
	// bansByHour
	m1e: "Bans issued by hour",
	bans24h: "Bans issued, last 24 hours",
	waf24h: "WAF blocks, last 24 hours",
	// whereFrom
	m1f: "Where attacks come from",
	// alertsByCountry
	m1g: "alerts by country, the ten with most",
	// colourBlue
	m1h: "Blue",
	// colourYellow
	m1i: "Yellow",
	// colourPink
	m1j: "Pink",
	// colourPurple
	m1k: "Purple",
	// colourTeal
	m1l: "Teal",
	// colourOrange
	m1m: "Orange",

	// Traffic
	// originCommunity
	m1n: "Community blocklist",
	// originDetections
	m1o: "Your detections",
	// originManual
	m1p: "Manual",
	// originOther
	m1q: "Other",
	// trafficDiscarded
	m1r: "Malicious traffic discarded",
	// trafficWaiting
	m1s: "The first metrics sample sets the baseline. Traffic appears after the next sync.",
	// packetsDiscarded
	m1t: "Packets discarded",
	// shareDiscarded
	m1u: "Share of traffic discarded",
	// shareOf
	m1v: "{share} of {processed} packets the firewall bouncer checked",
	// webRequests
	m1w: "Web requests",
	// requestsInspected
	m1x: "Requests inspected by AppSec",
	// requestsBlocked
	m1y: "Requests blocked",
	// challengeFunnel
	m1z: "Bot challenge",
	challenges: "Challenges",
	challenge_requested: "Requested",
	challenge_submitted: "Submitted",
	challenge_accepted: "Accepted",
	challenge_rejected: "Rejected",
	challenge_exempt: "Exempt",
	// challengesDay
	m20: "bot challenges at each stage, last 24 hours",
	// challengesRange
	m21: "bot challenges at each stage, last {days} days",
	// bansBySource
	m22: "Active bans by source",
	// activeDecisions
	m23: "Active decisions",
	// activeDecisionsNow
	m24: "active decisions now, by source",
	// colCommunityReason
	m25: "Community blocklist reason",
	// colDecisions
	m26: "Decisions",
	// trafficNote
	m27: "From the security engine's and the firewall bouncer's own metrics, sampled with each sync since {age}.",
	// discardedWeek
	m28: "Discarded this week",
	// packetsShort
	m29: "{count} packets",

	// Alerts explorer
	// allKinds
	m2a: "All kinds",
	// colKind
	m2b: "Kind",
	// colDecision
	m2c: "Decision",
	// noAlertsHere
	m2d: "No stored alerts match.",
	period1h: "1 hour",
	period24h: "24 hours",
	period3d: "3 days",
	period7d: "7 days",
	period30d: "30 days",
	// periodRet
	m2e: "Everything kept",
	// periodRetDays
	m2f: "{days} days (all kept)",
	// periodVisit
	m2g: "Since last visit",
	// periodRange
	m2h: "{from} to {to}",
	// dimIp
	m2i: "Source IP",
	// dimBehaviour
	m2j: "Behaviour",
	// dimPath
	m2k: "Target path",
	// dimEngine
	m2l: "Engine",
	// alertsByEngine
	m2m: "Alerts by engine",
	// alertsByEngineLine
	m2n: "alerts by the CrowdSec agent that raised them",
	// seenByEngines
	m2o: { one: "seen by {count} engine", other: "seen by {count} engines" },
	// bhExploit
	m2p: "HTTP exploit",
	// bhScan
	m2q: "HTTP scan",
	// bhCrawl
	m2r: "HTTP crawl",
	// bhBot
	m2s: "Bot",
	// bhSsh
	m2t: "SSH brute force",
	// bhManual
	m2u: "Manual",
	// bhGeneric
	m2v: "Generic",
	any: "Any",
	unknown: "Unknown",
	other: "Other",
	// filterIp
	m2w: "IP address or CIDR range",
	// applyFilters
	m2x: "Apply filters",
	// filterBy
	m2y: "Filter",
	// changeBreakdown
	m2z: "Change breakdown",
	// colShare
	m30: "Share",
	// colWhen
	m31: "When",
	// colSource
	m32: "Source",
	// colTarget
	m33: "Target",
	// colKey
	m34: "Key",
	// colValue
	m35: "Value",
	// colUserAgent
	m36: "User agent",
	// colRule
	m37: "Rule",
	// explorerCount
	m38: { one: "{formatted} alert matches.", other: "{formatted} alerts match." },
	// explorerPartial
	m39: "This period holds more stored alerts than a page reads, so the oldest are left out. Pick a shorter one.",
	// explorerNotRead
	m3a: "Alerts not read this time",
	// groupByIp
	m3b: "Group by IP",
	// eachAlert
	m3c: "Show each alert",
	// groupsCount
	m3d: { one: "{count} address. Rows {from} to {to}.", other: "{count} addresses. Rows {from} to {to}." },
	// alertsOver
	m3e: { one: "{count} alert", other: "{count} alerts over {span}" },
	// spanUnderMinute
	m3f: "under a minute",
	// firstSeen
	m3g: "first {time}",
	// firstSeenLabel
	m3h: "First seen",
	// detectWaf
	m3i: "WAF",
	// detectLog
	m3j: "Log",
	// detectBoth
	m3k: "WAF and log",
	// decisionsN
	m3l: { one: "{count} decision", other: "{count} decisions" },
	// decisionEnded
	m3m: "{type}, ended",
	// plusMore
	m3n: "+{count} more",
	// viewAlerts
	m3o: "View alerts",
	// alertDetail
	m3p: "Alert detail",
	// hintBanned
	m3q: "Banned now",
	// hintSeenBefore
	m3r: "Seen before",
	hints: "Hints",
	// backToExplorer
	m3s: "All addresses",
	// backToAlerts
	m3t: "Back",
	// alertsFrom
	m3u: "Alerts from {ip}",
	// decisionsActive
	m3v: "Active decision",
	// bannedFor
	m3w: "{remaining} left",
	// alertTitle
	m3x: "Alert {id}: {scenario}",
	started: "Started",
	// eventsCount
	m3y: "Events",
	message: "Message",
	// alertMeta
	m3z: "Meta",
	// alertEvents
	m40: "Events ({count} of {total})",
	ended: "Ended",
	// noDecisionsOnAlert
	m41: "No decisions on this alert.",
	// andMore
	m42: "And {count} more.",
	// alertNotShown
	m43: "Alert {id} is not one of this site's alerts in CrowdSec.",
	// removeBan
	m44: "Remove ban",
	// removeBanText
	m45: "Every active decision on exactly {value} is removed. Bouncers drop them on their next poll.",
	// reviewBanOf
	m46: "Review a ban of {value}",
	delete: "Delete",
	// deleteAlertTitle
	m47: "Delete this alert?",
	// deleteAlertText
	m48: "Alert {id} ({scenario} from {ip}) is deleted from CrowdSec. This cannot be undone.",
	// deleteNote
	m49: "Delete shows once an alert's decisions ended over two minutes ago: deleting an alert deletes its decisions where bouncers never hear of it. Lift a ban with Remove ban instead.",

	// Decisions page
	// colType
	m4a: "Type",
	// colOrigin
	m4b: "Origin",
	// colRemaining
	m4c: "Remaining",
	// decisionsCount
	m4d: {
		one: "{count} active decision, {bans} banned addresses.",
		other: "{count} active decisions, {bans} banned addresses.",
	},
	// decisionsTruncated
	m4e: "Read from the newest {count} alerts with an active decision: there may be more.",
	// decisionsNotRead
	m4f: "List not read this time",
	// decisionsNotReadDetail
	m4g: "The change used this request's share of calls. Read the page again to see it.",
	// noActiveDecisions
	m4h: "No active decisions.",
	// blocklistCount
	m4i: {
		one: "Also enforcing {formatted} address from the CrowdSec community blocklist and lists, as of {age}. They are counted, not listed.",
		other: "Also enforcing {formatted} addresses from the CrowdSec community blocklist and lists, as of {age}. They are counted, not listed.",
	},
	// blocklistTooMany
	m4j: "Also enforcing the CrowdSec community blocklist: too many addresses to count, as of {age}.",
	// alreadyBlocklisted
	m4k: "The CrowdSec community blocklist already blocks it.",
	// onlyBlocklisted
	m4l: "{value} is blocked only by the CrowdSec community blocklist or a list, which CrowdSec would add back. To let it through, add it to a CrowdSec allowlist.",
	remove: "Remove",
	// removeTitle
	m4m: "Remove this decision?",
	// removeText
	m4n: "The {type} on {value} is removed. Bouncers drop it on their next poll.",
	// remainingDays
	m4o: "{days} d {hours} h",
	// remainingHours
	m4p: "{hours} h {minutes} min",
	// remainingMinutes
	m4q: "{minutes} min",
	// remainingSeconds
	m4r: "{seconds} s",
	// banTitle
	m4s: "Ban an address in CrowdSec",
	// protectedCaller
	m4t: "Your address",
	// protectedSite
	m4u: "This site",
	// protectedLapi
	m4v: "CrowdSec LAPI host",
	// protectedSetting
	m4w: "Protected addresses setting",
	// callerUnknown
	m4x: "Not in this request, so a ban cannot be checked against it",
	// notLookedUp
	m4y: "Not looked up yet. A ban review or the setup check looks it up.",
	// protectedBuiltIn
	m4z: "A ban never covers private, loopback, link-local, CGNAT (Tailscale's 100.64.0.0/10 too), multicast or unspecified space, a range wider than /16 or /48, or a CrowdSec allowlist entry. IPv6 that carries IPv4 is checked as that IPv4 address.",
	// protectedInvalid
	m50: "These protected address entries are not addresses and protect nothing: {entries}.",
	// fieldAddress
	m51: "Address or range",
	// fieldDuration
	m52: "Duration",
	// fieldType
	m53: "Type",
	// fieldNote
	m54: "Note",
	// fieldNoteHint
	m55: "Why, recorded with the decision",
	duration_1h: "1 hour",
	duration_4h: "4 hours",
	duration_24h: "24 hours",
	duration_7d: "7 days",
	duration_30d: "30 days",
	// typeBan
	m56: "Ban",
	// typeCaptcha
	m57: "Captcha",
	// reviewBan
	m58: "Review ban",
	// reviewTitle
	m59: "Ready to ban",
	// reviewWhat
	m5a: "{type} {value} for {duration}.",
	// reviewChecks
	m5b: "Every protection passed, the CrowdSec allowlist included. Ban runs them all again.",
	// ownChecked
	m5c: "It is not your own address.",
	// ownNotChecked
	m5d: "Could not confirm this is not your own address: this request carried none.",
	// banNow
	m5e: "Ban",
	// banConfirmTitle
	m5f: "Add this decision?",

	// Setup check
	// setupTitle
	m5g: "CrowdSec setup check",
	// setupAllGood
	m5h: "Everything the numbers depend on is in place.",
	// setupProblems
	m5i: {
		one: "{count} problem stops or distorts the numbers.",
		other: "{count} problems stop or distort the numbers.",
	},
	// backToSecurity
	m5j: "Back to CrowdSec",
	// checkAgain
	m5k: "Check again",
	// colCheck
	m5l: "Check",
	// colStatus
	m5m: "Status",
	// colDetails
	m5n: "Details",
	// statusOk
	m5o: "OK",
	// statusProblem
	m5p: "Problem",
	// statusWaiting
	m5q: "Waiting",
	// statusSkipped
	m5r: "Not checked",
	// checkSettings
	m5s: "Settings",
	// checkTimeZone
	m5t: "Time zone",
	// checkEngineMetrics
	m5u: "Engine metrics",
	// checkFirewallMetrics
	m5v: "Firewall metrics",
	// metricsOff
	m5w: "Not set: its traffic charts are off.",
	// metricsOk
	m5x: "Answers, {count} series read: {names}.",
	// metricsNone
	m5y: "Answers, but none of the series the charts read: {expected}.",
	// metricsDeferred
	m5z: "Not checked: the DNS lookup used this check's calls. Press Check again.",
	// checkUrl
	m60: "LAPI URL",
	// checkLogin
	m61: "Login",
	// checkUserAgent
	m62: "User-Agent",
	// checkRead
	m63: "Read access",
	// checkChanges
	m64: "Changes",
	// checkProtections
	m65: "Ban protections",
	// checkScheduler
	m66: "Scheduled sync",
	// checkLastSync
	m67: "Last sync",
	// settingsSaved
	m68: "Saved.",
	// encryptionHint
	m69: "The password is saved encrypted with EMDASH_ENCRYPTION_KEY: run npx emdash secrets generate and set it on the site.",
	// needsSettings
	m6a: "Needs the settings above.",
	// needsUrl
	m6b: "Needs a usable LAPI URL.",
	// needsLogin
	m6c: "Needs a working login.",
	// urlInvalid
	m6d: "{url} is not a usable LAPI URL. It is LAPI's HTTPS base, for example https://www.example.com/crowdsec-lapi.",
	// urlPrivate
	m6e: "{url} is a private or internal address, which EmDash refuses to fetch. Publish LAPI on a public HTTPS hostname, as the README shows.",
	// urlNotHttps
	m6f: "The LAPI URL {url} is plain HTTP, and the plugin only uses HTTPS: the machine password and the token would cross the internet readable.",
	// timeZoneInvalid
	m6g: "The Time zone setting, {zone}, is not one this server knows. The sync waits for an IANA name such as Australia/Sydney.",
	// localSiteName
	m6h: "Bans are refused: {name} is a local name, which cannot be looked up to protect the site. Use public hostnames for the site and the LAPI.",
	// urlUserinfo
	m6i: "The LAPI URL has a user name or password in it, so it is never used. Remove it: the machine ID and password have their own settings.",
	// loginOk
	m6j: "Logged in as {machine}.",
	// userAgentOk
	m6k: "Sent as {ua}, which LAPI accepts.",
	// userAgentMaybe
	m6l: "Sent as {ua}. LAPI refuses a login whose User-Agent is not name/version, so a proxy that replaces it causes the refusal above.",
	// readOk
	m6m: "GET /v1/alerts answers.",
	// changesOffDetail
	m6n: "Off: the plugin only reads.",
	// changesOnDetail
	m6o: "On: administrators can ban, remove decisions and delete alerts.",
	// protectionsLiteral
	m6p: "The site and the LAPI are addresses, so no lookup is needed.",
	// protectionsOk
	m6q: {
		one: "Protected: {site}, {lapi}, and {count} protected address entry.",
		other: "Protected: {site}, {lapi}, and {count} protected address entries.",
	},
	// schedulerNotScheduled
	m6r: "The sync is not scheduled yet. Opening the dashboard schedules it.",
	// schedulerWaiting
	m6s: "Scheduled every {interval}, not run yet. If it has not run after {interval}, the site runs no scheduled tasks.",
	// schedulerOk
	m6t: "Last run {age}, scheduled every {interval}.",
	// schedulerStale
	m6u: "Last run {age}, but scheduled every {interval}: the site's scheduler is not running on time.",
	// schedulerNeverRan
	m6v: "Scheduled {age} to run every {interval}, and never run: the site's scheduler is not running.",
	// schedulerRefreshStuck
	m6w: "A requested sync was due {age} and has not run: the site's scheduler is not running.",
	// schedulerHowTo
	m6x: "On Cloudflare Workers, scheduled tasks need a Cron Trigger in wrangler.jsonc and the scheduled handler from EmDash's deployment guide.",

	// Problems: each one sentence naming the fix
	// notConfigured
	m6y: "CrowdSec is not configured yet: add {parts} in the plugin's settings.",
	part_lapiUrl: "the LAPI URL",
	part_machineId: "the machine ID",
	part_machinePassword: "the machine password",
	// noNetwork
	m6z: "The plugin cannot make network requests: its network permission is not granted.",
	// storageUnavailable
	m70: "The plugin's storage collections are not available.",
	// loginRefused
	m71: "LAPI refused the login (401). Check the machine ID and password, and that no proxy replaces the User-Agent.",
	// tokenRefused
	m72: "LAPI refused the session token twice. Check that the machine still exists (cscli machines list).",
	// routeRefused
	m73: "The proxy refused {route} (403). Admit it for this site's address, as the README shows.",
	// routeMissing
	m74: "LAPI has no {route} at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	// notLapi
	m75: "There is no LAPI login at this URL (404). Check the LAPI URL: it is the base, without /v1.",
	// notJson
	m76: "The LAPI URL answered with a web page, not JSON (HTTP {status}): a sign-in page or another site is in front of it.",
	// unexpectedAnswer
	m77: "LAPI answered in a form this plugin does not know.",
	// rateLimited
	m78: "LAPI or its proxy limited the request rate (429). The next sync tries again.",
	// httpStatus
	m79: "LAPI answered HTTP {status}.",
	// lapiSaid
	m7a: "LAPI answered HTTP {status}: {message}",
	unreachable: "LAPI could not be reached: {detail}",
	// blockedHost
	m7b: "EmDash refused the LAPI URL as a private or internal address: {detail}",
	// tooLarge
	m7c: "LAPI's answer was over the 8 MiB a plugin may receive. The next try asks for fewer.",
	redirected: "The LAPI URL answered with a redirect (HTTP {status}). The plugin follows none, so the password never goes elsewhere: set the URL the redirect points at.",
	// allowlistUnreadable
	m7d: "The ban was not added: LAPI's allowlist check answered in a form the plugin cannot read. Check that the proxy admits POST /v1/allowlists/check.",
	// metricsUnreachable
	m7e: "The metrics URL could not be reached: {detail}",
	// metricsRefused
	m7f: "The proxy refused the metrics URL (403). Admit GET on it for this site's address.",
	// metricsHttp
	m7g: "The metrics URL answered HTTP {status}.",
	// metricsNotPrometheus
	m7h: "The metrics URL answered with a web page instead of Prometheus metrics: a sign-in or challenge page is in front of it.",
	// dnsFailed
	m7i: "Looking up {name} for the ban protections failed: {detail}",
	// dnsEmpty
	m7j: "{name} has no address, so a ban cannot be checked against it. Check the site URL and the LAPI URL.",
	// dnsJustLoaded
	m7k: "The site's and the LAPI's addresses were just looked up for the ban protections. Try again.",

	// Write refusals and results
	// changesOff
	m7l: "Changes are off. An administrator can turn on Allow changes in the plugin's settings.",
	// adminOnly
	m7m: "Only an administrator can change CrowdSec.",
	// invalidAddress
	m7n: "That is not an IPv4 or IPv6 address or a CIDR range.",
	// invalidDuration
	m7o: "Pick a duration from the list: 1h, 4h, 24h, 7d or 30d.",
	// invalidType
	m7p: "The type is ban or captcha.",
	// invalidId
	m7q: "That is not an id.",
	// rangeTooWide
	m7r: "Refused: the range is wider than {widest}, the widest a ban may cover.",
	// reservedAddress
	m7s: "Refused: private, loopback, link-local, CGNAT, multicast and reserved space is never banned.",
	// ownAddress
	m7t: "Refused: it covers your own address ({match}).",
	// mcpClientAddress
	m7u: "Refused: it covers the address this MCP client connects from ({match}).",
	// hostBits
	m7v: "That range has bits set after its prefix. Write it as {meant}.",
	// protectedInvalidRefuse
	m7w:
		"Changes are refused until the Protected addresses setting is fixed: {entries} cannot be read. Only IP addresses and CIDR ranges are accepted there, not hostnames.",
	// siteAddress
	m7x: "Refused: it covers this site's address ({match}).",
	// lapiAddress
	m7y: "Refused: it covers the CrowdSec LAPI host's address ({match}).",
	// settingAddress
	m7z: "Refused: it covers {match} from the Protected addresses setting.",
	allowlisted: "Refused: the address is on a CrowdSec allowlist.",
	// allowlistedReason
	m80: "Refused: the address is on a CrowdSec allowlist ({reason}).",
	// banDone
	m81: "Added: {type} on {value} for {duration}. Bouncers apply it on their next poll.",
	// banDoneUnchecked
	m82: "Added: {type} on {value} for {duration}. Could not confirm this is not your own address: the request carried none.",
	// banDoneUncheckedMcp
	m83:
		"Added: {type} on {value} for {duration}. Could not check it against the address this MCP client connects from: the request carried none.",
	// decisionRemoved
	m84: "Removed decision {id}. Bouncers drop it on their next poll.",
	// decisionGone
	m85: "That decision is already gone.",
	// noActiveBan
	m86: "No active decision is on exactly {value}.",
	// removedAll
	m87: { one: "Removed {count} decision on {value}.", other: "Removed {count} decisions on {value}." },
	// removedSome
	m88: "Removed {count} decisions on {value}. {remaining} remain: run it again.",
	// alertGone
	m89: "Alert {id} is not in CrowdSec any more, so it was taken off the list.",
	// alertHasActiveDecision
	m8a: "Refused: alert {id} still has an active decision. Remove it first, then delete the alert two minutes later.",
	// alertDecisionJustEnded
	m8b:
		"Refused: a decision of alert {id} ended less than two minutes ago, and bouncers may not have heard yet. Try again in two minutes.",
	// alertDeleted
	m8c: "Deleted alert {id}.",
	// alertDecisionUnknown
	m8d: "Refused: a decision of alert {id} has an end time the plugin cannot read, so it may still be in force. Remove the decision first.",
	// tryAgain
	m8e: "The login used this request's share of calls. Try again.",
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
	const message: Message | undefined = catalogues[lang][key];
	// A problem stored under a key an earlier version used (0.1.0's keys
	// were longer) shows as that key until the next sync replaces it.
	if (message === undefined) return String(key);
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
	if (problem.key === "m6y") {
		const missing = String(problem.params?.missing ?? "")
			.split(",")
			.filter(Boolean);
		const parts = missing.map((key) => {
			const part = `part_${key}`;
			return part in catalogues[lang] ? t(lang, part as MessageKey) : key;
		});
		return t(lang, "m6y", { parts: listOf(lang, parts) });
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
