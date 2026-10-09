You need CrowdSec 1.7 or later with its Local API on a public HTTPS hostname (EmDash refuses private addresses), and `EMDASH_ENCRYPTION_KEY` set on the site (`npx emdash secrets generate` makes one).

1. On the CrowdSec host, create a machine for the plugin: `sudo cscli machines add emdash-crowdsec --auto -f /root/emdash-crowdsec.yaml`. The file holds its ID and password.
2. Publish LAPI behind a reverse proxy that admits only the EmDash server's address and only these routes: `POST /v1/watchers/login`, `GET /v1/alerts`, `GET /v1/alerts/{id}`. For changes, also `POST /v1/alerts`, `DELETE /v1/alerts/{id}`, `DELETE /v1/decisions/{id}` and `POST /v1/allowlists/check`. Never admit `DELETE /v1/decisions` without an id. Exempt the path from any bot challenge. The README has nginx and Traefik examples for a single host.
3. Install the plugin from the Registry. Its one permission is network access: to your LAPI URL, and to `cloudflare-dns.com` while changes are on.
4. In Plugins, open the plugin's settings: enter the LAPI URL (without `/v1`), the machine ID and password, and your time zone. Save.
5. Open Plugins, CrowdSec, and select Check setup. Fix anything it names.
6. To allow bans and unbans, turn on Allow changes and add your server and home addresses to Protected addresses.

On Cloudflare Workers, the sync needs the Cron Trigger from EmDash's deployment guide. To use the MCP tools, turn on Agent access for the plugin under Plugins.
