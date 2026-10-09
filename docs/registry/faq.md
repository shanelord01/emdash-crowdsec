**Does the plugin make my CrowdSec LAPI public?**
No. EmDash only lets a plugin call public HTTPS hostnames, so LAPI is reached through a path on one, but the proxy in front admits only your EmDash server's address and only the routes the plugin uses. Everyone else gets 403, and every request also needs the plugin's own machine login. LAPI itself still listens on `127.0.0.1`. The README shows the setup.

**The login fails with "incorrect Username or Password", but the password is right.**
LAPI refuses a User-Agent that is not `name/version`. A proxy that replaces the plugin's causes this.

**The setup check says a route was refused (403).**
Your proxy does not admit it for the EmDash server. Add it as the README shows.

**Why are the first days' numbers low?**
History is read newest first, a window at a time. The page says while it is still being read.

**Why is the Decisions list shorter than `cscli decisions list`?**
It lists your own decisions. The community blocklist and lists hold thousands more, shown as one count above the list.

**Why is the top list approximate?**
Each day keeps its 25 most frequent values, so rarer ones are undercounted.

**Why can't I delete this alert?**
Deleting it would delete its decisions where bouncers never hear of it. Remove the decision, then delete the alert two minutes later.

**Why was my ban refused?**
The message names the rule that protects the address. The README lists them all.

**Does the plugin store the LAPI token?**
No. It logs in once per run. The machine password is saved encrypted.

**Where do the traffic charts come from?**
Your engine's and firewall bouncer's own metrics, never CrowdSec's cloud. Set their URLs in the settings.

**Which time zone are the days in?**
The Time zone setting, `Australia/Sydney` unless changed. A name the server does not know pauses the sync until it is fixed, and stored history is kept.
