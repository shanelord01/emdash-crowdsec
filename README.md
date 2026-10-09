# CrowdSec for EmDash

An unofficial plugin. It is not affiliated with, endorsed by or supported by CrowdSec.

CrowdSec in the EmDash admin. A dashboard card, three admin pages and nine MCP tools show the alerts, bans and top threats your CrowdSec Local API (LAPI) records, and, if you turn it on, let administrators ban an address, lift a ban or delete an old alert.

It is a sandboxed plugin: it runs in EmDash's plugin sandbox, reads LAPI over HTTPS with a machine login of its own, and keeps a compact copy of the alerts in plugin storage. It needs no content access and stores no LAPI token.

## What's new in 0.1.1

- **The CrowdSec alerts page is an explorer.** Pick a period from an hour to everything kept, or since your last visit, and step it back and forward. Tabs split the alerts by kind. Two panels break them down by source address, behaviour, country, AS organisation, scenario, target path, kind or engine, each with its top three, its share and a histogram. Filters show as chips. The table groups the alerts by address, or lists them one by one, and opens a view of one address and a live detail of one alert. See [The Alerts explorer](#the-alerts-explorer).
- **Engines.** Each alert keeps the CrowdSec agent that raised it, so a LAPI that collects alerts from several hosts can be read host by host. The Engine names setting gives them names.
- **A new MCP tool, `alerts_explorer`.** EmDash asks for Agent access again after the update, because a tool was added. Turn it back on under Plugins.
- **Demo data is gone.** The plugin needs a reachable CrowdSec LAPI. An install that used demo data shows "not configured" until the LAPI settings are entered, and its demo rows are cleared on the first sync after that.
- Shorter times and narrower tables, and the 90-day CrowdSec page draws three days a bar.

## Requirements

- EmDash 1.0.1 or later with a sandbox runner. The suite is run against EmDash 1.0.1.
- CrowdSec 1.7 or later, with its Local API reachable from the EmDash server on a public HTTPS hostname. EmDash refuses to fetch private addresses, internal names and `localhost`, so a LAPI on `127.0.0.1:8080` has to be published through a reverse proxy first (see below).
- `EMDASH_ENCRYPTION_KEY` set on the site, so the machine password can be saved encrypted (`npx emdash secrets generate` makes one).

There is no demo mode: trying the plugin needs a LAPI the site can reach.

## Setting it up

### A machine for the plugin

Create a LAPI machine (a watcher) just for the plugin, on the CrowdSec host:

```sh
sudo cscli machines add emdash-crowdsec --auto -f /root/emdash-crowdsec.yaml
```

The file holds the machine ID (`login`) and the password. `-f` writes them to a file of their own, so the machine's existing credentials file is left alone. Copy the two values into the plugin's settings and delete the file.

### Publishing LAPI for the plugin only

This part is written for a single host: EmDash and CrowdSec on the same server, EmDash usually in a Docker container, and nginx or Traefik in front. The examples use `www.example.com` for the site, `198.51.100.10` for the server's public address and `<emdash-container-ip>` for the EmDash container's address on its Docker network. Replace them with your own.

#### Why a public hostname

EmDash looks up the hostname a plugin calls with DNS over HTTPS (Cloudflare) and refuses it if it resolves to a private address. It then connects with an ordinary `fetch`, which honours the container's `/etc/hosts`. So the LAPI URL has to be a public HTTPS hostname, such as `https://www.example.com/crowdsec-lapi`, but the connection itself can be sent to the proxy over an internal network with a hosts entry.

The hostname is public, the endpoint is not open:

- the proxy admits only the EmDash container's address, and every other address gets 403;
- it admits only the routes the plugin uses, listed below, and refuses everything else under the path, bulk deletes included;
- every request still needs the plugin's own machine login, whose password is stored encrypted in EmDash.

LAPI keeps listening on `127.0.0.1` or the host. It is never exposed.

#### Routes and methods

The plugin uses exactly these routes and no others.

| Route | Used for | Needed |
| --- | --- | --- |
| `POST /v1/watchers/login` | The login, once per invocation that needs LAPI | Always |
| `GET /v1/alerts` | The sync, the CrowdSec decisions page, the tools | Always |
| `GET /v1/alerts/{id}` | An alert's detail in the Alerts explorer, and checking an alert before deleting it | Always |
| `POST /v1/alerts` | Adding a ban or captcha | With Allow changes on |
| `DELETE /v1/alerts/{id}` | Deleting one alert | With Allow changes on |
| `DELETE /v1/decisions/{id}` | Removing one decision | With Allow changes on |
| `POST /v1/allowlists/check` | Checking a ban target against your CrowdSec allowlists | With Allow changes on |
| `GET /metrics` of the engine and the firewall bouncer | The [traffic charts](#traffic-charts) | With a metrics URL set |

For a read-only install, admit the first three. For changes, admit all seven. The metrics paths are `GET` only.

Every other path under the prefix must be refused (403 or 404), so nothing falls through to the website. Never admit `DELETE /v1/decisions` without an id: with a filter it removes the matching decisions, and with no filter at all it removes every decision LAPI holds. Do not admit `DELETE /v1/alerts` without an id either, since it deletes alerts in bulk. The plugin sends neither, and the proxy should refuse both regardless.

#### Which address the proxy sees

- **nginx on the host, EmDash in Docker.** The container's requests to its own public hostname are delivered locally and arrive from the container's address on its Docker network, for example `172.18.0.2`. Admit that address, or the network (`172.18.0.0/16`). Better still, give the container a fixed address and admit only that.
- **Traefik and EmDash both in Docker, through the published port.** Requests that leave the container and come back in through the host's published port arrive from the gateway of Traefik's network, for example `172.18.0.1`, through Docker's userland proxy. Every container and process on the host shares that address, so admitting it is a weak check. Outside visitors keep their real addresses.
- **Traefik and EmDash on a shared network (recommended).** Put EmDash and Traefik on one Docker network with a declared subnet. Give Traefik a fixed address (`ipv4_address`), and give the EmDash container `extra_hosts: ["www.example.com:<traefik-ip>"]` and a fixed address of its own. Admit only that address. The requests then never leave the Docker network, and no other container can pass the check.

To find the address the proxy really sees, make one request from inside the EmDash container, then look for it in the proxy's access log:

```sh
docker exec <emdash-container> node -e "fetch('https://www.example.com/robots.txt?src-test=1')"
```

In nginx's log it is the first field of the `src-test` line. In Traefik's JSON access log it is `ClientHost`.

Under gVisor (`runtime: runsc`) the container cannot use Docker's embedded DNS at `127.0.0.11`, so network aliases do not resolve. `extra_hosts` still works.

#### nginx

With LAPI on `127.0.0.1:8080`, published at `/crowdsec-lapi/` and admitting only `<emdash-container-ip>`:

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

# In the server block of www.example.com.
location /crowdsec-lapi/ {
    allow <emdash-container-ip>;
    deny  all;
    if ($crowdsec_lapi_route = 0) { return 403; }

    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
}

# Only with a metrics URL set.
location = /crowdsec-lapi/metrics/engine {
    allow <emdash-container-ip>;
    deny  all;
    limit_except GET { deny all; }
    proxy_pass http://127.0.0.1:6060/metrics;
}

location = /crowdsec-lapi/metrics/firewall {
    allow <emdash-container-ip>;
    deny  all;
    limit_except GET { deny all; }
    proxy_pass http://127.0.0.1:60601/metrics;
}
```

`$uri` holds the path without the query string, so `DELETE /crowdsec-lapi/v1/decisions?ip=...` matches no line and gets a 403. Any other path under `/crowdsec-lapi/` gets a 403 too.

#### Traefik

A file provider configuration for Traefik v3, `dynamic/crowdsec-lapi.yml`, with `websecure` standing for your HTTPS entrypoint. LAPI is reached at `host.docker.internal:8080`, which needs `extra_hosts: ["host.docker.internal:host-gateway"]` on the Traefik container if it is not defined there already. See [Reaching CrowdSec from a container](#reaching-crowdsec-from-a-container) when LAPI listens on `127.0.0.1` only.

```yaml
http:
  middlewares:
    crowdsec-lapi-allow:
      ipAllowList:
        sourceRange: ["<emdash-container-ip>/32"]
    crowdsec-lapi-deny:
      ipAllowList:
        sourceRange: ["127.0.0.255/32"]   # matches nothing: always 403
    crowdsec-lapi-strip:
      stripPrefix:
        prefixes: ["/crowdsec-lapi"]
    crowdsec-metrics-path:
      replacePath:
        path: /metrics

  routers:
    crowdsec-lapi:
      entryPoints: [websecure]
      rule: "Host(`www.example.com`) && ((Method(`POST`) && Path(`/crowdsec-lapi/v1/watchers/login`)) || ((Method(`GET`) || Method(`POST`)) && Path(`/crowdsec-lapi/v1/alerts`)) || ((Method(`GET`) || Method(`DELETE`)) && PathRegexp(`^/crowdsec-lapi/v1/alerts/[0-9]+$`)) || (Method(`DELETE`) && PathRegexp(`^/crowdsec-lapi/v1/decisions/[0-9]+$`)) || (Method(`POST`) && Path(`/crowdsec-lapi/v1/allowlists/check`)))"
      priority: 1000
      middlewares: [crowdsec-lapi-allow, crowdsec-lapi-strip]
      service: crowdsec-lapi
      tls: {}
    crowdsec-metrics-engine:
      entryPoints: [websecure]
      rule: "Host(`www.example.com`) && Method(`GET`) && Path(`/crowdsec-lapi/metrics/engine`)"
      priority: 1000
      middlewares: [crowdsec-lapi-allow, crowdsec-metrics-path]
      service: crowdsec-metrics-engine
      tls: {}
    crowdsec-metrics-firewall:
      entryPoints: [websecure]
      rule: "Host(`www.example.com`) && Method(`GET`) && Path(`/crowdsec-lapi/metrics/firewall`)"
      priority: 1000
      middlewares: [crowdsec-lapi-allow, crowdsec-metrics-path]
      service: crowdsec-metrics-firewall
      tls: {}
    crowdsec-lapi-rest:
      entryPoints: [websecure]
      rule: "Host(`www.example.com`) && PathPrefix(`/crowdsec-lapi`)"
      priority: 900
      middlewares: [crowdsec-lapi-deny]
      service: crowdsec-lapi
      tls: {}

  services:
    crowdsec-lapi:
      loadBalancer:
        servers: [{ url: "http://host.docker.internal:8080" }]
    crowdsec-metrics-engine:
      loadBalancer:
        servers: [{ url: "http://host.docker.internal:6060" }]
    crowdsec-metrics-firewall:
      loadBalancer:
        servers: [{ url: "http://host.docker.internal:60601" }]
```

Leave out the write routes of the first rule for a read-only install, and the metrics routers without a metrics URL. Three things to watch:

- **Rules on one line.** Traefik rejects a rule that contains a line break ("expected ')', found newline"), and YAML's `>-` keeps the line breaks of indented lines. Keep each rule a single quoted string.
- **No CrowdSec middleware on these routers.** Do not attach the CrowdSec bouncer middleware to them: its bot challenge would answer the plugin with a 200 HTML page where it expects JSON. If the bouncer is attached to the whole entrypoint instead, exempt the `/crowdsec-lapi` path in its AppSec configuration.
- **Replace the file atomically.** Traefik watches the directory and can read a half-written file. Write a temporary file and rename it over the old one.

With nginx too, exempt the `/crowdsec-lapi/` path from any AppSec bot challenge, captcha or sign-in page on that hostname.

#### Reaching CrowdSec from a container

nginx on the host reaches LAPI on `127.0.0.1` directly. A proxy in a container cannot. Either:

- make LAPI listen on the Docker bridge address as well (`listen_uri: 172.17.0.1:8080` in CrowdSec's `config.yaml`), which changes the address every bouncer and agent on the host uses; or
- forward the port with a small `socat` service bound to the bridge address, leaving LAPI as it is.

An example systemd unit for the forward, one per port:

```ini
[Unit]
Description=Forward LAPI to the Docker bridge
After=docker.service

[Service]
DynamicUser=yes
ExecStart=/usr/bin/socat TCP-LISTEN:8080,bind=172.17.0.1,fork,reuseaddr TCP:127.0.0.1:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

The same forward reaches a metrics endpoint that only answers on a VPN interface such as Tailscale, which drops sources outside the tailnet.

A host firewall with a default deny (ufw, for example) also needs a rule that admits the proxy's network to ports 8080, 6060 and 60601:

```sh
sudo ufw allow from 172.18.0.0/16 to any port 8080 proto tcp
```

#### Metrics

- The security engine serves Prometheus metrics from the `prometheus:` block of `config.yaml`, on `127.0.0.1:6060` by default.
- The firewall bouncer's are off by default. In `crowdsec-firewall-bouncer.yaml`, set `prometheus.enabled: true`, `listen_addr: 127.0.0.1` and `listen_port: 60601`, then restart it. The restart briefly rebuilds its block sets.
- Neither endpoint has authentication, so publish them only through the same address-restricted proxy.

#### Checking it

- From the EmDash container: the login answers 200, `GET /v1/alerts?include_capi=false` answers 200, a route the plugin does not use answers 403, and each metrics URL answers 200.
- From anywhere else: every path under `/crowdsec-lapi` answers 403.
- Plugins, CrowdSec, Check setup: every check passes.

#### Cloudflare Workers

On Cloudflare Workers the plugin's requests leave from Cloudflare's network, which has no fixed address to admit. There the route list and the machine password are what protect LAPI.

### The User-Agent

LAPI refuses a watcher login whose User-Agent is not of the form `name/version`, with the same 401 "incorrect Username or Password" a wrong password gets. The plugin sends `User-Agent: emdash-crowdsec/<version>` on every request. If a proxy between EmDash and LAPI replaces the User-Agent, the login fails. The setup check names this when the login is refused.

### Settings

Open Plugins, then the plugin's settings.

- **LAPI URL.** The LAPI's base on HTTPS, without `/v1`, for example `https://www.example.com/crowdsec-lapi`. Plain HTTP, private addresses and URLs with a user name or password in them are refused everywhere, and no request is made to them. Redirects are not followed, so the password is never sent to another address.
- **Machine ID** and **Machine password.** From `cscli machines add`. The password is saved encrypted with `EMDASH_ENCRYPTION_KEY`.
- **Sync every.** 15 minutes unless changed. 30 minutes and an hour are offered.
- **Keep alerts for.** 90 days unless changed, 7 to 400. The first syncs read this far back, newest first, and older rows are deleted every night. LAPI keeps its own alerts by its own rules.
- **Include simulated alerts.** Off unless changed. Alerts from scenarios in simulation mode, which decide nothing.
- **Time zone.** An IANA name, `Australia/Sydney` unless changed. Days, charts, ranges, retention and times are in this zone, since EmDash does not tell a plugin the site's own. An unknown name pauses the sync until it is fixed, and the pages use `Australia/Sydney` meanwhile.
- **Engine metrics URL** and **Firewall metrics URL.** Optional, empty unless set. The security engine's and the firewall bouncer's Prometheus endpoints, for the [traffic charts](#traffic-charts). They follow the LAPI URL's rules: HTTPS only, no user name or password in them, no redirects followed. A URL that cannot be used turns its charts off and shows on the setup check. The alerts still sync.
- **Allow changes.** Off unless changed. See [Changes](#changes).
- **Protected addresses.** Addresses and ranges a ban must never cover, separated by commas or new lines.
- **Engine names.** Optional. Names for the CrowdSec agents that send alerts to this LAPI, `machine_id = Name`, one per line or separated by commas: `edge-machine = Edge, web-machine = Web`. `cscli machines list` shows the ids. Without a name, the pages show the machine id, a long generated one cut to its first 8 characters (`3f9e2c7a…`), and an alert's detail shows the whole id.

Changing the LAPI URL, the time zone or Include simulated alerts to another usable value clears the stored alerts and reads them again, since the stored rows would no longer match. A value the plugin cannot use (a plain HTTP or private URL, an unknown time zone, a cleared password) pauses the sync instead and keeps every stored row, so a typo never costs history that LAPI may already have removed.

Then open Plugins, CrowdSec, and select Check setup. It checks the settings, the URL, a fresh login, the User-Agent, read access, the ban protections when changes are on, the scheduled sync and the last sync, and says in one sentence what to fix for anything that fails.

On Cloudflare Workers the sync needs the Cron Trigger from EmDash's deployment guide. The setup check shows the snippet when the scheduler is not running.

## What it shows

**The CrowdSec card** on the dashboard: alerts in the last 24 hours against the 24 before, active bans now, alerts by kind (WAF, bot challenge, behaviour), packets discarded this week against the week before when the traffic charts are on, the top three scenarios, when the last sync ran, and a Refresh button that asks for a sync.

**CrowdSec** (`/security`), over the last 24 hours (by hour) or 7, 30 or 90 days (by day): alerts, bans issued and WAF blocks against the period before, active bans, the [traffic charts](#traffic-charts) when they are on, alerts by kind, bans issued, a chart of where attacks come from (the ten countries with most alerts, their names spelt out), and the top scenarios, source addresses, countries, AS organisations and targeted paths. Top lists add up each day's 25 most frequent values, so a value that never made a day's top 25 is undercounted. In the 24-hour view they cover today and yesterday. EmDash draws no chart legend, so a line under each chart names its series by colour.

**CrowdSec alerts** (`/security/alerts`): the Alerts explorer, below.

**CrowdSec decisions** (`/security/decisions`): the decisions LAPI enforces now, read live, with address, scenario, type, origin, time remaining, country and AS organisation, sortable by expiry. It reads 100 alerts with an active decision at a time and says when there may be more.

When more than one engine raised alerts in the range, the CrowdSec page also draws alerts by engine. A site with one CrowdSec agent sees no change.

### The Alerts explorer

- **Periods.** 1 hour (in 5-minute bars), 24 hours and 3 days (by hour), 7 and 30 days (by local day, today included), everything kept, and Since last visit, which starts at your visit before this one (a visit is a page load more than 30 minutes after the last). ◀ and ▶ step a period back and forward. Over 45 days, a bar holds two or more days.
- **Kinds.** All, WAF, Bot challenge, Behaviour and Manual.
- **Two breakdown panels.** Source IP and Behaviour to start with. Change breakdown switches a panel to Country (the name spelt out), AS organisation, Scenario, Target path, Kind or Engine. Each shows its top three values with their count and share, the rest as Other, and a stacked histogram with the series named under it. Filter adds a value as a filter.
- **Behaviour** is read from the scenario name: `vpatch-*` and CVE ids are HTTP exploit, `http-*probing`, `http-sensitive-files` and path traversal are HTTP scan, `http-crawl*` and `http-bad-user-agent` are HTTP crawl, the AppSec bot challenge is Bot, anything with `ssh` is SSH brute force, a ban by hand is Manual, and the rest is Generic. The table is in `src/explorer/behaviour.ts`.
- **Filters.** An address or CIDR range (an address inside the range matches), country, scenario, behaviour, AS organisation, target path and, when more than one engine appears, engine. Each active filter shows as a chip that removes it, and every panel and the table follow them all.
- **The table** groups the alerts by source address, newest first, 20 to a page: when (the last alert, "N alerts over" their span, the first), the source (address, country, AS organisation and the hints), details (WAF or log, the top two scenarios, decisions, and "seen by N engines" when more than one saw it) and the top paths. Show each alert lists them one by one instead, 25 to a page, with the engine when there is more than one.
- **An address's view** lists its alerts, its active decision with the time left, and, for administrators with Allow changes on, Ban or Remove ban behind the same checks as the CrowdSec decisions page.
- **An alert's detail** reads the alert live from LAPI (`GET /v1/alerts/{id}`): its meta, up to ten events with the target, user agent and rule, its decisions, and the engine with its whole id. Old alerts can be deleted from here.
- **Hints, not reputation.** The plugin never asks CrowdSec's cloud, so there are no reputation badges. Banned now means a decision on the address is still running. Seen before means it had alerts on days before the period.

`alerts_explorer` gives an agent the same numbers.

**How the alerts are stored.** Grouping by address over a week means reading every alert of the week. Kept one row per alert, a site with 230 alerts a day holds 1,600 rows a week, and a page that may make ten bridge calls reads 100 rows a call. Rows summed per address could not take a filter on a scenario or a path across addresses. So the plugin keeps an alert log: each alert in a few hundred bytes, in arrays. Each sync step writes one chunk per local day it brought alerts for, and an hourly maintenance run merges each closed day's chunks into one row, or several of up to 1,500 alerts on a very busy day. Ninety days are then about 90 rows, read in one or two queries, and every number on the page is worked out exactly from them. A page reads up to 400 rows. When a period holds more, the page says so and leaves the oldest out. Alerts stored by 0.1.0 move into the log about a hundred a minute after the update, in a chain of runs of their own while the sync goes on, and they have no engine, so they show as Unknown.

### The community blocklist

CrowdSec's Central API pulls the community blocklist into LAPI, and any lists you subscribe to come in the same way. They arrive as alerts of their own, with an empty source and thousands of decisions each: on a busy engine, tens of thousands of addresses. They are not this site's events, so the plugin leaves them out of every chart, top list, count and table, and asks LAPI to leave them out of its answers (`include_capi=false`). The CrowdSec decisions page and `active_decisions` show them as one line instead, "Also enforcing 24,004 addresses from the CrowdSec community blocklist and lists", counted once a day by a task of its own. That read is several megabytes, so only the count and its time are kept, and an answer too large to read is kept as "too many to count". A lookup of one address (`ip_alerts`, the ban review, `remove_ban`) still says when the blocklist blocks it. `remove_ban` never removes a blocklist decision, since CrowdSec adds it back on its next pull: to let such an address through, add it to a CrowdSec allowlist.

Alert kinds come from LAPI: `waf` for AppSec rules and virtual patches, `bot-detection` and the `appsec-bot-challenge-*` scenarios for the bot challenge, `manual` for bans added by hand, and everything else as behaviour.

Editors and administrators see all of it. Authors and contributors do not.

## Traffic charts

Alerts say what CrowdSec noticed. The traffic charts show what it then did, from the numbers the security engine and the firewall bouncer keep themselves, read from their own Prometheus endpoints on your server. Nothing comes from CrowdSec's cloud or Console. They are off until a metrics URL is set.

- **Malicious traffic discarded:** packets and bytes the firewall bouncer dropped over the range, against the period before, split by where the decision came from: the community blocklist (and any lists), your own detections, and manual bans. A stacked chart shows each day (or hour). From `fw_bouncer_dropped_packets` and `fw_bouncer_dropped_bytes`.
- **Share of traffic discarded:** dropped packets as a share of the packets the bouncer checked (`fw_bouncer_processed_packets`).
- **Web requests:** requests the AppSec engine inspected (`cs_appsec_reqs_total`) and blocked (`cs_appsec_block_total`) per day, and the bot challenge for the range: requested, submitted, accepted, rejected and exempt (`cs_appsec_challenge_*_total`).
- **Active bans by source:** the decisions in force now by origin, and the community blocklist's top reasons (`http:scan`, `ssh:bruteforce`), from `cs_active_decisions`.

The plugin samples both endpoints on the sync's schedule, in a task of its own, which the sync starts or stops when the metrics URLs change, and stores what each counter counted since the last sample: per local day for the retention period, and per hour for the last 48 hours. The first sample only sets the baseline. A counter lower than before was reset (the bouncer restarted, or CrowdSec restarted or reloaded), and its new value is what it counted since. A source that does not answer counts nothing until it answers again. Changing a metrics URL or the time zone starts a new baseline.

`traffic_summary` gives the same figures to an agent.

## MCP tools

Turn on Agent access for the plugin under Plugins to use them.

| Tool | Answers | Permission |
| --- | --- | --- |
| `security_summary` | Alerts by kind, decisions and bans over 7, 30 or 90 days, with the period before, the last 24 hours and the active ban count | Editor |
| `top_threats` | The most frequent scenarios, source addresses, countries, AS organisations and paths | Editor |
| `active_decisions` | The decisions in force now, read live | Editor |
| `ip_alerts` | The alerts for one address or range, read live, matching the source exactly | Editor |
| `traffic_summary` | Packets and bytes discarded by origin, their share, AppSec requests and blocks, and the bot challenge, over 7, 30 or 90 days | Editor |
| `alerts_explorer` | The stored alerts of a period, kind and filters (address or range, country, scenario, behaviour, AS organisation, path, engine): the total, two breakdowns and the alerts grouped by address with their engines and hints | Editor |
| `ban_ip` | Adds a ban or captcha, with every check the CrowdSec decisions page runs | Administrator |
| `remove_ban` | Removes the active decisions on exactly one address or range | Administrator |
| `delete_alert` | Deletes one alert, with the same guard as the CrowdSec alerts page | Administrator |

The write tools need Allow changes on as well. Adding a tool makes EmDash ask for Agent access again when the plugin is updated.

## Changes

With **Allow changes** on, administrators can:

- ban an address or range, or make it solve a captcha, for 1 hour, 4 hours, 24 hours, 7 days or 30 days, from the CrowdSec decisions page, an address's view in the Alerts explorer, or `ban_ip`;
- remove a decision from its row on the CrowdSec decisions page, every active decision on an address from its view in the explorer, or with `remove_ban`;
- delete an old alert from its detail in the explorer, or with `delete_alert`.

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

The CrowdSec decisions page shows the protected set above the ban form.

### Deleting alerts

Deleting an alert in LAPI deletes its decisions with it, and a decision deleted that way is never reported to a bouncer that had not polled yet: the ban stays in the firewall until it expires. So the plugin deletes an alert only once all of its decisions ended more than two minutes ago, and refuses when a decision's end time cannot be read. To lift a ban, remove the decision instead. Deleting an alert also takes it out of the alert log.

## How it reads LAPI

LAPI's alert search takes `since` and `until` as durations and `limit` as a count, with no offset. The plugin reads in bounded windows:

- A **forward** step reads the last 24 hours, at most 200 alerts. When even the oldest of a full batch was created after the previous forward step, the alerts between were not reached, and that span is kept as a gap.
- A **backfill** step reads the newest 30 days of the newest gap, at most 200 alerts, and shrinks the gap by what it read. The first syncs open one gap over the whole retention period, so the newest alerts arrive first.
- While gaps remain, each backfill step schedules the next a minute later. A site with 230 alerts a day has 90 days of history in about two hours on Node. On Cloudflare Workers the pace is set by the site's Cron Trigger.
- Syncs take turns: of every four, one reads forward, two read history (or forward, once there is none left) and one counts the active bans. At the default 15 minutes, a site with no history left to read reads forward three times an hour and counts the bans hourly. Refresh asks for a forward read and a ban count straight away, and every change asks for a ban count.
- The CrowdSec decisions page, `active_decisions` and `ip_alerts` read LAPI live each time. The other pages and tools read only the stored rows.
- The community blocklist is counted once a day, and once soon after the plugin is installed.
- One sync runs at a time. A tick takes a lease on the sync state, and writes its result only if no other tick took the state meanwhile. A Refresh or a ban count that finds the lease taken runs a minute later.

An answer over the 8 MiB a plugin may receive halves the batch for the next try, and steps that fit grow it back. When one second holds more alerts than a batch, the batch grows (to 500 at most) and, if that is too large, the read steps past that second. At an average of 13 KB per alert, 200 alerts are about 2.6 MB. Windows overlap at their edges, and every stored day records the alert ids it has counted, so no alert is counted twice. Durations are measured on LAPI's clock, from each answer's Date header.

The plugin stores a few hundred bytes per alert (time, kind, scenario, address, country, AS organisation, path, decision, engine) in the alert log, and one row per day with its totals, its top lists and the ids it has counted, at most 200 ranges of them. Nothing else from the alerts is kept.

## Bridge calls

A sandboxed invocation may make ten bridge calls on Cloudflare, and each storage, KV, settings, cron and network call is one. The plugin's largest invocations use exactly ten:

| Invocation | Calls at most |
| --- | --- |
| A sync step: the lease (2), settings, the login, the search, the day rows read, two writes, the state, the next catch-up run | 10 |
| The daily DNS refresh for the ban protections | 10 |
| The setup check with the DNS lookup | 10 |
| The ban protections' first DNS lookup during a ban | 7 |
| A ban from the CrowdSec decisions page, with the list read again | 9 |
| A ban review, with the allowlist check and the list read again | 7 |
| The Alerts explorer: a first visit (the visit's write), the day rows before the period and four log queries | 8 |
| An alert's detail in the explorer: the login and the GET | 4 |
| Deleting an alert from its detail: the login, the GET, the DELETE, up to three log queries and the write | 9 |
| A ban from an address's view in the explorer, with its alerts read again | 10 |
| The hourly maintenance: the settings, then the merge of a hundred chunks of the alert log (7), or at 3 am the prune | 9 |
| A run moving 0.1.0's alert rows into the log, with the next run's schedule | 8 |
| `alerts_explorer` | 7 |
| `remove_ban` (it removes up to five decisions per call and says how many remain) | 9 |
| The CrowdSec page over 90 days, with the traffic charts | 6 |
| The dashboard card | 9 |
| A metrics sample: the state, the settings, both endpoints, the state's write and the day's row | 7 |

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
