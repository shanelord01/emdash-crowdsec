/**
 * Page paths and action ids, in one place so the pages can link to each
 * other and `src/plugin.ts` can route without import cycles.
 */

export const SECURITY_PATH = "/security";
export const ALERTS_PATH = "/security/alerts";
export const DECISIONS_PATH = "/security/decisions";

export const WIDGET_REFRESH = "cs:widget:refresh";

export const RANGE_ACTION = "cs:range";
export const PAGE_REFRESH = "cs:page:refresh";
export const SETUP_ACTION = "cs:setup";

/** Alerts page: the view travels after a `|` in the id (see `./alerts.ts`). */
export const ALERTS_VIEW = "cs:alerts:view";
export const ALERTS_TABLE = "cs:alerts:table";
export const ALERTS_SCENARIO = "cs:alerts:scenario";
export const ALERTS_DELETE = "cs:alerts:delete";

export const DECISIONS_TABLE = "cs:decisions:table";
export const DECISIONS_REFRESH = "cs:decisions:refresh";
export const DECISIONS_REMOVE = "cs:decisions:remove";
export const BAN_REVIEW = "cs:ban:review";
export const BAN_CONFIRM = "cs:ban:confirm";
