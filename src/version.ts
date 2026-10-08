/**
 * The plugin's version and the User-Agent every LAPI request carries.
 *
 * LAPI refuses a watcher login with 401 "incorrect Username or Password"
 * unless the User-Agent has the form `name/version`, so this is not
 * decoration. `tests/version.test.ts` keeps it equal to `package.json`.
 */
export const VERSION = "0.1.0";

export const USER_AGENT = `emdash-crowdsec/${VERSION}`;
