Report a security problem privately through the repository's advisory form: https://github.com/shanelord01/emdash-crowdsec/security/advisories/new

**What the plugin can reach**

Network requests only, to two places: the LAPI URL you enter, and, while Allow changes is on, `cloudflare-dns.com` to look up the site's and the LAPI host's addresses. It has no access to your content, users or media. It uses only the LAPI routes the README lists, never `DELETE /v1/decisions` with a filter, never a bulk alert delete, and follows no redirect, so the password is never sent to another host. Plain HTTP and URLs with credentials in them are refused.

**Credentials**

The machine password is saved encrypted with `EMDASH_ENCRYPTION_KEY`. The LAPI token is never stored: each run logs in and keeps it in memory. Give the plugin a machine of its own, and publish LAPI so only the EmDash server and only the plugin's routes get through.

**Who can do what**

Editors and administrators see the card, the pages and the read tools. Only administrators can change anything, and only with Allow changes on. On the pages the plugin checks the role itself. The write tools' routes are limited to administrators by EmDash.

**Ban protections**

A ban is refused, naming the rule, when it covers the requester's address (for an MCP tool, the client's egress), the site's or LAPI host's addresses, a Protected addresses entry, private, loopback, link-local, CGNAT (including Tailscale's 100.64.0.0/10), multicast or reserved space, a range wider than /16 or /48, or a CrowdSec allowlist entry, checked first since LAPI skips it for manual bans. IPv6 that carries IPv4 is judged by that IPv4 address, and Teredo is refused. A bad protected entry refuses every change.

**Deleting alerts**

An alert is deleted only once its decisions ended more than two minutes ago, since deleting it removes its decisions where bouncers never hear of it.
