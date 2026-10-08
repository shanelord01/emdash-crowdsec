# CrowdSec for EmDash

CrowdSec in the EmDash admin. A dashboard card, three admin pages and seven MCP tools show the alerts, bans and top threats your CrowdSec Local API (LAPI) records, and, if you turn it on, let administrators ban an address, lift a ban or delete an old alert.

It is a sandboxed plugin: it runs in EmDash's plugin sandbox, reads LAPI over HTTPS with a machine login of its own, and keeps a compact copy of the alerts in plugin storage. It needs no content access and stores no LAPI token.

## Requirements

- EmDash 1.0.1 or later with a sandbox runner. The suite is run against EmDash 1.0.1.
- CrowdSec 1.7 or later, with its Local API reachable from the EmDash server on a public HTTPS hostname. EmDash refuses to fetch private addresses, internal names and `localhost`, so a LAPI on `127.0.0.1:8080` has to be published through a reverse proxy first (see below).
- `EMDASH_ENCRYPTION_KEY` set on the site, so the machine password can be saved encrypted (`npx emdash secrets generate` makes one).

## Setting it up

### A machine for the plugin

Create a LAPI machine (a watcher) just for the plugin, on the CrowdSec host:

```sh
sudo cscli machines add emdash-crowdsec --auto -f /root/emdash-crowdsec.yaml
```

The file holds the machine ID (`login`) and the password. `-f` writes them to a file of their own, so the machine's existing credentials file is left alone. Copy the two values into the plugin's settings and delete the file.

### Publishing LAPI for the plugin only

#### Is the LAPI endpoint public?

The hostname is public, the endpoint is not open. EmDash only lets a plugin call public HTTPS hostnames, so LAPI has to sit behind one, for example `https://www.example.com/crowdsec-lapi`. The proxy in front of it then does the protecting:

- It admits only the EmDash server's address. Every other address gets 403, so the internet sees a path that refuses it.
- It admits only the routes the plugin uses, listed below. Bulk deletes and anything else are refused even for the EmDash server.
- Every request still needs the plugin's own machine login, whose password is stored encrypted in EmDash.

LAPI itself keeps listening on `127.0.0.1` only. Nothing else about it changes.


A LAPI machine can push alerts, add decisions and delete them. Publish it so the plugin can use only what it needs: the EmDash server's address and nothing else, and only the routes below.

The plugin uses exactly these routes and no others.

| Route | Used for | Needed |
| --- | --- | --- |
| `POST /v1/watchers/login` | The login, once per invocation that needs LAPI | Always |
| `GET /v1/alerts` | The sync, the Decisions page, the tools | Always |
| `GET /v1/alerts/{id}` | Checking an alert before deleting it | Always |
| `POST /v1/alerts` | Adding a ban or captcha | With Allow changes on |
| `DELETE /v1/alerts/{id}` | Deleting one alert | With Allow changes on |
| `DELETE /v1/decisions/{id}` | Removing one decision | With Allow changes on |
| `POST /v1/allowlists/check` | Checking a ban target against your CrowdSec allowlists | With Allow changes on |

For a read-only install, admit the first three. For changes, admit all seven.

Never admit `DELETE /v1/decisions` without an id. With a filter it removes the matching decisions, and with no filter at all it removes every decision LAPI holds. Do not admit `DELETE /v1/alerts` without an id either: it deletes alerts in bulk. The plugin sends neither, and the proxy should refuse both regardless.

Which address to admit depends on where EmDash runs. When EmDash runs in a Docker container on the same server as nginx, its requests to the server's own public hostname arrive from the container network, for example `172.18.0.2`, not from the public address. Check nginx's access log for a request the plugin makes, such as the setup check, and admit that network (`allow 172.18.0.0/16;`). If the container network is recreated it can get another subnet: update the `allow` line then.

An nginx example, with the LAPI on `127.0.0.1:8080`, published at `/crowdsec-lapi/` and admitting only an EmDash server at `198.51.100.10`:

```nginx
# In the http block.
map "$request_method $uri" $crowdsec_lapi_route {
    default                                         0;
    "~^POST /crowdsec-lapi/v1/watchers/login$"      1;
    "~^GET /crowdsec-lapi/v1/alerts$"               1;
    "~^GET /crowdsec-lapi/v1/alerts/[0-9]+$"        1;
    # Only with Allow changes on:
    "~^POST /crowdsec-lapi/v1/alerts$"              1;
    "~^DELETE /crowdsec-lapi/v1/alerts/[0-9]+$"     1;
    "~^DELETE /crowdsec-lapi/v1/decisions/[0-9]+$"  1;
    "~^POST /crowdsec-lapi/v1/allowlists/check$"    1;
}

# In the server block of the public HTTPS hostname.
location /crowdsec-lapi/ {
    allow 198.51.100.10;   # the EmDash server
    deny  all;
    if ($crowdsec_lapi_route = 0) { return 403; }

    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
}
```

`$uri` holds the path without the query string, so `DELETE /crowdsec-lapi/v1/decisions?ip=...` matches no line and gets a 403.

If an AppSec bot challenge, a captcha or a sign-in page guards that hostname, exempt the `/crowdsec-lapi/` path from it. The plugin cannot answer a challenge, and a challenge page reaches it as HTML where it expects JSON.

On Cloudflare Workers the plugin's requests leave from Cloudflare's network, which has no fixed address to admit. There the route list and the machine password are what protect LAPI.

### The User-Agent

LAPI refuses a watcher login whose User-Agent is not of the form `name/version`, with the same 401 "incorrect Username or Password" a wrong password gets. The plugin sends `User-Agent: emdash-crowdsec/<version>` on every request. If a proxy between EmDash and LAPI replaces the User-Agent, the login fails. The setup check names this when the login is refused.

### Settings

Open Plugins, then the plugin's settings.

- **Data source.** CrowdSec Local API, or demo data. Demo data generates alerts so the pages can be tried without a LAPI, and it cannot be changed. Switching clears the stored alerts.
- **LAPI URL.** The LAPI's base on HTTPS, without `/v1`, for example `https://www.example.com/crowdsec-lapi`. Plain HTTP, private addresses and URLs with a user name or password in them are refused everywhere, and no request is made to them. Redirects are not followed, so the password is never sent to another address.
- **Machine ID** and **Machine password.** From `cscli machines add`. The password is saved encrypted with `EMDASH_ENCRYPTION_KEY`.
- **Sync every.** 15 minutes unless changed. 30 minutes and an hour are offered.
- **Keep alerts for.** 90 days unless changed, 7 to 400. The first syncs read this far back, newest first, and older rows are deleted every night. LAPI keeps its own alerts by its own rules.
- **Include simulated alerts.** Off unless changed. Alerts from scenarios in simulation mode, which decide nothing.
- **Time zone.** An IANA name, `Australia/Sydney` unless changed. Days, charts, ranges, retention and times are in this zone, since EmDash does not tell a plugin the site's own. An unknown name pauses the sync until it is fixed, and the pages use `Australia/Sydney` meanwhile.
- **Allow changes.** Off unless changed. See [Changes](#changes).
- **Protected addresses.** Addresses and ranges a ban must never cover, separated by commas or new lines.

Changing the LAPI URL, the time zone or Include simulated alerts to another usable value clears the stored alerts and reads them again, since the stored rows would no longer match. A value the plugin cannot use (a plain HTTP or private URL, an unknown time zone, a cleared password) pauses the sync instead and keeps every stored row, so a typo never costs history that LAPI may already have removed.

Then open Plugins, Security, and select Check setup. It checks the settings, the URL, a fresh login, the User-Agent, read access, the ban protections when changes are on, the scheduled sync and the last sync, and says in one sentence what to fix for anything that fails.

On Cloudflare Workers the sync needs the Cron Trigger from EmDash's deployment guide. The setup check shows the snippet when the scheduler is not running.

## What it shows

**The Security card** on the dashboard: alerts in the last 24 hours against the 24 before, active bans now, alerts by kind (WAF, bot challenge, behaviour), the top three scenarios, when the last sync ran, and a Refresh button that asks for a sync.

**Security** (`/security`), over 7, 30 or 90 days: alerts, bans issued and WAF blocks against the period before, active bans, alerts by kind per day, bans issued per day, and the top scenarios, source addresses, countries, AS organisations and targeted paths. Top lists add up each day's 25 most frequent values, so a value that never made a day's top 25 is undercounted.

**Security alerts** (`/security/alerts`): the stored alerts, newest first, 25 to a page, with time, kind, scenario, address, country, AS organisation, targeted path and decision, filtered by kind and scenario.

**Security decisions** (`/security/decisions`): the decisions LAPI enforces now, read live, with address, scenario, type, origin, time remaining, country and AS organisation, sortable by expiry. It reads 100 alerts with an active decision at a time and says when there may be more.

Alert kinds come from LAPI: `waf` for AppSec rules and virtual patches, `bot-detection` and the `appsec-bot-challenge-*` scenarios for the bot challenge, `manual` for bans added by hand, and everything else as behaviour.

Editors and administrators see all of it. Authors and contributors do not.

## MCP tools

Turn on Agent access for the plugin under Plugins to use them.

| Tool | Answers | Permission |
| --- | --- | --- |
| `security_summary` | Alerts by kind, decisions and bans over 7, 30 or 90 days, with the period before, the last 24 hours and the active ban count | Editor |
| `top_threats` | The most frequent scenarios, source addresses, countries, AS organisations and paths | Editor |
| `active_decisions` | The decisions in force now, read live | Editor |
| `ip_alerts` | The alerts for one address or range, read live, matching the source exactly | Editor |
| `ban_ip` | Adds a ban or captcha, with every check the Decisions page runs | Administrator |
| `remove_ban` | Removes the active decisions on exactly one address or range | Administrator |
| `delete_alert` | Deletes one alert, with the same guard as the Alerts page | Administrator |

The write tools need Allow changes on as well.

## Changes

With **Allow changes** on, administrators can:

- ban an address or range, or make it solve a captcha, for 1 hour, 4 hours, 24 hours, 7 days or 30 days, from the Decisions page or `ban_ip`;
- remove a decision from its row on the Decisions page, or every active decision on an address with `remove_ban`;
- delete an old alert from its row on the Alerts page, or with `delete_alert`.

Editors never see these controls, and the plugin refuses an editor's write even if one were sent. On the admin pages the plugin checks the administrator role itself, because EmDash sends every page interaction to one route that editors may read. The MCP write tools have routes of their own, which EmDash itself limits to administrators.

A ban is added the way `cscli decisions add` adds one: one alert with one decision, origin `cscli`, its reason `manual 'ban' from 'emdash-crowdsec' by <name>` and the note typed with it. Bouncers apply it on their next poll. Removing a decision deletes it by id, and bouncers drop it on their next poll too.

Every write confirms first. The ban form only reviews the ban: every rule runs, the CrowdSec allowlist included, and the page then offers a Ban button whose confirmation names the address, the duration and whether your own address could be checked. Ban runs every rule again before it adds the decision. Remove and Delete ask before they act. `remove_ban` and `ip_alerts` search an IPv4-mapped address in the IPv4 form LAPI stores.

### What a ban never covers

A ban is refused, with the rule that refused it named, when it covers:

- **your own address**: the one the request came from, from EmDash's request metadata and every forwarding header (`X-Real-IP`, `X-Forwarded-For`, `CF-Connecting-IP`, `True-Client-IP`). When no address can be found, the ban still goes ahead and its confirmation says the plugin could not confirm it is not your own address. For an MCP tool this is the address the MCP client connects from, which may be a server or a proxy rather than yours;
- **this site's addresses** and **the LAPI host's addresses**, looked up with DNS over HTTPS at `cloudflare-dns.com` and cached for a day. The sync refreshes the lookup in the background while changes are on, and so does the setup check. When the cache is empty, a ban looks the names up and asks to be tried again rather than going ahead unchecked. A failed lookup is tried again six hours later, and the ban count goes on meanwhile. A local site name (`localhost`, a name without a dot) cannot be looked up, so bans are refused until the site URL is public;
- **an entry of the Protected addresses setting**. While any entry there is not an address or a CIDR range (a hostname, say), every change is refused until it is fixed;
- **private, loopback, link-local, CGNAT (including Tailscale's `100.64.0.0/10`), multicast, unspecified or reserved space**;
- **a range wider than /16 for IPv4 or /48 for IPv6**;
- **an address on a CrowdSec allowlist**. LAPI skips its own allowlist check for an alert that carries decisions, so the plugin asks `POST /v1/allowlists/check` first. A range counts when any address inside it is allowlisted, and an answer the plugin cannot read refuses the ban.

IPv6 forms that carry an IPv4 address are judged as that IPv4 address: IPv4-mapped (`::ffff:a.b.c.d`), SIIT translated (`::ffff:0:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`). A range that would cover one of those blocks is refused, and so are the deprecated IPv4-compatible `::/96`, local-use NAT64 `64:ff9b:1::/48` and Teredo `2001::/32`, whose IPv4 addresses cannot be read reliably. A range with bits set after its prefix (`1.2.3.4/16`) is refused with the range it was probably meant as. Forwarding headers that carry a port (`203.0.113.5:4711`, `[2001:db8::1]:443`) are read without it.

The Decisions page shows the protected set above the ban form.

### Deleting alerts

Deleting an alert in LAPI deletes its decisions with it, and a decision deleted that way is never reported to a bouncer that had not polled yet: the ban stays in the firewall until it expires. So the plugin deletes an alert only once all of its decisions ended more than two minutes ago, and refuses when a decision's end time cannot be read. To lift a ban, remove the decision instead. An alert LAPI no longer has is taken off the Alerts page.

## How it reads LAPI

LAPI's alert search takes `since` and `until` as durations and `limit` as a count, with no offset. The plugin reads in bounded windows:

- A **forward** step reads the last 24 hours, at most 200 alerts. When even the oldest of a full batch was created after the previous forward step, the alerts between were not reached, and that span is kept as a gap.
- A **backfill** step reads the newest 30 days of the newest gap, at most 200 alerts, and shrinks the gap by what it read. The first syncs open one gap over the whole retention period, so the newest alerts arrive first.
- While gaps remain, each backfill step schedules the next a minute later. A site with 230 alerts a day has 90 days of history in about two hours on Node. On Cloudflare Workers the pace is set by the site's Cron Trigger.
- Syncs take turns: of every four, one reads forward, two read history (or forward, once there is none left) and one counts the active bans. At the default 15 minutes, a site with no history left to read reads forward three times an hour and counts the bans hourly. Refresh asks for a forward read and a ban count straight away, and every change asks for a ban count.
- The Decisions page, `active_decisions` and `ip_alerts` read LAPI live each time. The other pages and tools read only the stored rows.
- One sync runs at a time. A tick takes a lease on the sync state, and writes its result only if no other tick took the state meanwhile. A Refresh or a ban count that finds the lease taken runs a minute later.

An answer over the 8 MiB a plugin may receive halves the batch for the next try, and steps that fit grow it back. When one second holds more alerts than a batch, the batch grows (to 500 at most) and, if that is too large, the read steps past that second. At an average of 13 KB per alert, 200 alerts are about 2.6 MB. Windows overlap at their edges, and every stored day records the alert ids it has counted, so no alert is counted twice. Durations are measured on LAPI's clock, from each answer's Date header.

The plugin stores a few hundred bytes per alert (time, kind, scenario, address, country, AS organisation, path, decision) and one row per day with its totals, its top lists and the ids it has counted, at most 200 ranges of them. Nothing else from the alerts is kept.

## Bridge calls

A sandboxed invocation may make ten bridge calls on Cloudflare, and each storage, KV, settings, cron and network call is one. The plugin's largest invocations use exactly ten:

| Invocation | Calls at most |
| --- | --- |
| A sync step: the lease (2), settings, the login, the search, the day rows read, two writes, the state, the next catch-up run | 10 |
| The daily DNS refresh for the ban protections | 10 |
| The setup check with the DNS lookup | 10 |
| The ban protections' first DNS lookup during a ban | 7 |
| A ban from the Decisions page, with the list read again | 9 |
| A ban review, with the allowlist check and the list read again | 7 |
| Deleting an alert from the Alerts page, with the page read again | 8 |
| `remove_ban` (it removes up to five decisions per call and says how many remain) | 9 |
| The Security page over 90 days | 4 |
| The dashboard card | 5 |

`tests/budget.test.ts` counts the worst case of every hook, page action, write and tool.

## Development

```sh
pnpm install
pnpm typecheck
pnpm test        # emdash-plugin validate, then vitest
pnpm build
pnpm bundle
./scripts/compat-matrix.sh 1.0.1
```

## Licence

MIT. See [LICENSE](LICENSE).
