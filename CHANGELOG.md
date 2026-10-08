# emdash-crowdsec

## 0.1.0

First release. CrowdSec in the EmDash admin, read from your Local API with a machine login of its own:

- a Security card on the dashboard with the last 24 hours' alerts against the 24 before, the active bans, alerts by kind and the top scenarios
- a Security page over 7, 30 or 90 days, with alerts by kind and bans issued per day, and the top scenarios, sources, countries, AS organisations and targeted paths
- an Alerts page with the stored alerts, filtered by kind and scenario, and a Decisions page with the decisions in force now
- a setup check that names the fix for each thing the numbers depend on
- seven MCP tools: four that read and three that change
- demo data, for trying the plugin without a LAPI

With Allow changes on, administrators can ban an address or range, remove decisions and delete old alerts. A ban never covers your own address, the site's or the LAPI host's addresses, the Protected addresses setting, private or reserved space, a range wider than /16 or /48, or an address on a CrowdSec allowlist.

Days run in the new Time zone setting, `Australia/Sydney` unless changed.
