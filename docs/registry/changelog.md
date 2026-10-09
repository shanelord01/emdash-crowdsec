## 0.1.1

- The CrowdSec alerts page is an explorer: periods from an hour to everything kept, or since your last visit, kind tabs, two switchable breakdowns with histograms, filters as chips, alerts grouped by address with a view of each address and a live detail of each alert, and Banned now and Seen before hints.
- Engines: each alert keeps the CrowdSec agent that raised it, as a breakdown, a filter, a column and a CrowdSec page chart when there is more than one, named in the new Engine names setting.
- A new MCP tool, `alerts_explorer`. EmDash asks for Agent access again after the update.
- Stored alerts move into a compact alert log on the first syncs after the update.
- Demo data is removed: the plugin needs a reachable LAPI. An install that used it asks for the LAPI settings, and its demo rows are cleared once they are set.
- Shorter times and narrower tables, a 90-day page in three-day bars, and the metrics sampler follows its settings without a dashboard visit.

## 0.1.0

First release.

- A CrowdSec card on the dashboard, a CrowdSec page over 7, 30 or 90 days, a CrowdSec alerts page and a live CrowdSec decisions page.
- A setup check that names the fix for each thing the numbers depend on.
- Traffic charts from your engine's and firewall bouncer's own metrics, a 24-hour view and a chart of where attacks come from.
- Eight MCP tools: `security_summary`, `top_threats`, `active_decisions`, `ip_alerts`, `traffic_summary`, and, with Allow changes on, `ban_ip`, `remove_ban` and `delete_alert`.
- Optional bans, unbans and alert deletion for administrators, with protections for your own address, the site's and the LAPI host's addresses, a Protected addresses setting, private and reserved space, wide ranges and CrowdSec allowlists.
- Days in a Time zone setting, `Australia/Sydney` unless changed.
- The community blocklist shown as one daily count of addresses, never as rows.
- Demo data, for trying the plugin without a LAPI.
