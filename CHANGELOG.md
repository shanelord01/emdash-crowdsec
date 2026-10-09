# emdash-crowdsec

## 0.1.1

The CrowdSec alerts page is now an explorer:

- periods of 1 hour, 24 hours, 3 days, 7 days, 30 days, everything kept, and Since last visit, each stepped back and forward with ◀ and ▶
- tabs for All, WAF, Bot challenge, Behaviour and Manual
- two breakdown panels, Source IP and Behaviour to start with, each switchable to Country, AS organisation, Scenario, Target path or Kind, with its top three values, their share, Other and a stacked histogram (by hour up to 3 days, by local day beyond)
- filters for an address or CIDR range, country, scenario, behaviour, AS organisation and target path, shown as chips that remove them, applied to every panel and the table
- the alerts grouped by source address, newest first, or listed one by one, with a view of one address (its alerts, its active decision, Ban or Remove ban) and a live detail of one alert (meta, events with target, user agent and rule, decisions)
- local hints in place of reputation badges: Banned now and Seen before. Nothing is asked of CrowdSec's cloud
- engines: each alert keeps the CrowdSec agent that raised it (`machine_id`), for a LAPI that collects alerts from several hosts. Engine is a breakdown and a filter, a column when more than one engine appears, and part of each alert's detail, and the grouped table says when several engines saw an address. The CrowdSec page adds alerts by engine when more than one raised alerts in the range. A new Engine names setting names them (`machine_id = Name`). Alerts stored before the update show as Unknown

A new MCP tool, `alerts_explorer`, gives an agent the same numbers, engines included. **Adding a tool means EmDash asks again for Agent access when you update:** turn it back on under Plugins to keep using the MCP tools.

Stored alerts move into an alert log that keeps them in daily arrays instead of one row each, so a page reads a year of history in a few queries. The move runs about a hundred alerts a minute after the update while the sync goes on, and the counts do not change. The nightly prune is now an hourly maintenance run that also merges each closed day's alerts.

**Demo data is removed**, to keep the plugin inside the registry's 128 KB limit. The Data source setting is gone, and the plugin needs a CrowdSec LAPI the site can reach. An install that used demo data shows "not configured" on the setup check and pauses the sync until the LAPI URL, the machine ID and the password are entered. Its demo rows are then cleared by the first sync, as for any change of LAPI.

Also:

- the clean-up of community blocklist rows that pre-release builds stored is gone: 0.1.0 never stored any, and every 0.1.0 install has already run it

- times in tables are short ("9 Oct 11:54") and the alerts and decisions tables are narrower, so they fit the page
- the 90-day CrowdSec page draws three days a bar, so it stays inside EmDash's limit on page size with the traffic charts on
- changing the source or the metrics URLs now starts or stops the metrics sampler on the next sync, without a dashboard visit

## 0.1.0

First release. CrowdSec in the EmDash admin, read from your Local API with a machine login of its own:

- a CrowdSec card on the dashboard with the last 24 hours' alerts against the 24 before, the active bans, alerts by kind and the top scenarios
- a CrowdSec page over 7, 30 or 90 days, with alerts by kind and bans issued per day, and the top scenarios, sources, countries, AS organisations and targeted paths
- a CrowdSec alerts page with the stored alerts, filtered by kind and scenario, and a CrowdSec decisions page with the decisions in force now
- a setup check that names the fix for each thing the numbers depend on
- traffic charts from the security engine's and the firewall bouncer's own metrics, when their URLs are set: malicious traffic discarded by origin, its share, web requests and the bot challenge, and active bans by source
- a 24-hour view by hour, beside 7, 30 and 90 days, and a chart of where attacks come from
- eight MCP tools: five that read and three that change
- demo data, for trying the plugin without a LAPI

With Allow changes on, administrators can ban an address or range, remove decisions and delete old alerts. A ban never covers your own address, the site's or the LAPI host's addresses, the Protected addresses setting, private or reserved space, a range wider than /16 or /48, or an address on a CrowdSec allowlist.

Days run in the new Time zone setting, `Australia/Sydney` unless changed.

The community blocklist and lists are left out of every chart, count and list and shown as one daily count of addresses. Rows a pre-release build stored from them are taken out on update, and their days are counted again.
