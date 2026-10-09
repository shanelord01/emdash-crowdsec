# emdash-crowdsec

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
