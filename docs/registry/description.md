CrowdSec in the EmDash admin, read from your CrowdSec Local API with a machine login of its own.

**On the dashboard:** a Security card with the last 24 hours' alerts against the 24 before, the bans in force now, alerts by kind (WAF, bot challenge, behaviour) and the top scenarios.

**Security page:** 7, 30 or 90 days of alerts by kind and bans issued per day, with the top scenarios, source addresses, countries, AS organisations and targeted paths.

**Alerts and Decisions pages:** the stored alerts, filtered by kind and scenario, and the decisions LAPI enforces now, read live and sorted by expiry.

**MCP tools:** a summary, top threats, active decisions and the alerts for one address, plus three that change things.

**Optional changes:** with Allow changes on, administrators can ban an address or range for a fixed time, remove a decision and delete old alerts. A ban never covers your own address, the site's, the LAPI host's, your protected addresses, private space or an allowlisted address.

Days run in your time zone. Demo data lets you try it without a LAPI.
