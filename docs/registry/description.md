CrowdSec in the EmDash admin, read from your CrowdSec Local API with a machine login of its own.

**On the dashboard:** a CrowdSec card with the last 24 hours' alerts against the 24 before, the bans in force now, alerts by kind (WAF, bot challenge, behaviour) and the top scenarios.

**CrowdSec page:** 7, 30 or 90 days of alerts by kind and bans issued per day, with the top scenarios, source addresses, countries, AS organisations and targeted paths.

**CrowdSec alerts:** an explorer of the stored alerts. Periods from an hour to everything kept or since your last visit, kind tabs, two breakdowns with histograms, filters by address range, country, scenario, behaviour, network, path or engine, alerts grouped by address, and a live detail of each alert.

**CrowdSec decisions:** the decisions LAPI enforces now, read live and sorted by expiry.

**Traffic charts:** malicious traffic discarded by the firewall bouncer, split by community blocklist, your detections and manual bans, its share of all traffic, web requests inspected and blocked, the bot challenge, and active bans by source. From your own engine's and bouncer's metrics, never CrowdSec's cloud.

**MCP tools:** a summary, top threats, an alerts explorer, traffic, active decisions and the alerts for one address, plus three that change things.

**Optional changes:** with Allow changes on, administrators can ban an address or range for a fixed time, remove a decision and delete old alerts. A ban never covers your own address, the site's, the LAPI host's, your protected addresses, private space or an allowlisted address.

Days run in your time zone. It needs a CrowdSec LAPI the site can reach.
