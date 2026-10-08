**Does the plugin make my CrowdSec LAPI public?**
No. EmDash only lets a plugin call public HTTPS hostnames, so LAPI is reached through a path on one, but the proxy in front admits only your EmDash server's address and only the routes the plugin uses. Everyone else gets 403, and every request also needs the plugin's own machine login. LAPI itself still listens on `127.0.0.1`. The README shows the setup.

**The login fails with "incorrect Username or Password", but the password is right.**
LAPI also refuses a login whose User-Agent is not `name/version`. The plugin sends `emdash-crowdsec/<version>`. A proxy that replaces the User-Agent causes this.

**The setup check says a route was refused (403).**
Your proxy does not admit that route for the EmDash server's address. Add it as the README shows.

**Why are the numbers for the first days low?**
The first syncs read the newest alerts first and then history, a window at a time. The page says while history is still being read.

**Why is the top list approximate?**
Each day keeps its 25 most frequent values. A value that never made a day's top 25 is undercounted over a range.

**Why can't I delete this alert?**
Deleting an alert deletes its decisions where bouncers never hear of it, so the ban would stay in the firewall. Remove the decision first, then delete the alert two minutes later.

**Why was my ban refused?**
The message names the rule: your own address, the site's or the LAPI host's address, a protected address, private or reserved space, a range wider than /16 or /48, or a CrowdSec allowlist.

**Does the plugin store the LAPI token?**
No. It logs in once per run and keeps the token in memory. The machine password is saved encrypted.

**Which time zone are the days in?**
The Time zone setting, `Australia/Sydney` unless changed. A name the server does not know pauses the sync until it is fixed, and stored history is kept.
