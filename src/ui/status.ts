/**
 * The sentences the widget and the pages share: how fresh the numbers are
 * and what is wrong, if anything. A failure that would otherwise show as a
 * dashboard of zeroes reads as one sentence naming the fix.
 */

import { problemText, t, type Lang } from "../i18n.js";
import type { SourceId } from "../settings.js";
import type { SyncState } from "../sync/scheduler.js";
import { formatAge, formatTime } from "./format.js";

export function statusLine(state: SyncState, source: SourceId, now: Date, lang: Lang, zone: string): string {
	const parts: string[] = [];
	if (source === "demo") parts.push(t(lang, "demoData"));
	const age = formatAge(state.lastSync, now, lang);
	parts.push(age ? t(lang, "synced", { age }) : t(lang, "notSynced"));
	if ((state.gaps ?? []).length > 0 && state.head) {
		const newest = state.gaps!.reduce((max, gap) => (gap.to > max ? gap.to : max), state.gaps![0]!.to);
		parts.push(t(lang, "historyReading", { time: formatTime(newest, lang, zone) }));
	}
	const error = errorText(state, lang);
	if (error) {
		const errorAge = formatAge(state.lastErrorAt, now, lang);
		parts.push(errorAge ? t(lang, "lastAttemptFailedAge", { age: errorAge, error }) : t(lang, "lastAttemptFailed", { error }));
	}
	return parts.join(" · ");
}

export function emptyReason(state: SyncState, lang: Lang): string {
	return errorText(state, lang) ?? (state.lastSync ? t(lang, "syncedNoAlerts") : t(lang, "firstSyncPending"));
}

export function errorText(state: SyncState, lang: Lang): string | undefined {
	if (!state.lastProblem) return state.lastError;
	return problemText(lang, state.lastProblem);
}
