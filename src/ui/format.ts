/**
 * Formatting for the admin UI. Pure. Numbers, dates and relative times use
 * the catalogue language from `langOf()`, so they never mix with the text
 * around them.
 */

import { langOf, t, type Lang } from "../i18n.js";

export function formatCount(value: number, locale?: string): string {
	if (!Number.isFinite(value)) return "0";
	try {
		return new Intl.NumberFormat(locale ?? "en").format(value);
	} catch {
		return String(Math.trunc(value));
	}
}

/** "3 minutes ago". Null for a missing timestamp, so the caller decides what absent looks like. */
export function formatAge(iso: string | undefined | null, now: Date, locale?: string): string | null {
	if (!iso) return null;
	const then = Date.parse(iso);
	if (Number.isNaN(then)) return null;
	const seconds = Math.round((then - now.getTime()) / 1000);
	const abs = Math.abs(seconds);
	const [value, unit]: [number, Intl.RelativeTimeFormatUnit] =
		abs < 60 ? [seconds, "second"] : abs < 3600 ? [Math.round(seconds / 60), "minute"] : abs < 86_400 ? [Math.round(seconds / 3600), "hour"] : [Math.round(seconds / 86_400), "day"];
	try {
		return new Intl.RelativeTimeFormat(locale ?? "en", { numeric: "auto" }).format(value, unit);
	} catch {
		return `${value} ${unit}`;
	}
}

/** Seconds left as "3 h 41 min", "12 min", "40 s". */
export function formatRemaining(seconds: number, lang: Lang): string {
	const whole = Math.max(0, Math.round(seconds));
	const days = Math.floor(whole / 86_400);
	const hours = Math.floor((whole % 86_400) / 3600);
	const minutes = Math.floor((whole % 3600) / 60);
	if (days > 0) return t(lang, "remainingDays", { days, hours });
	if (hours > 0) return t(lang, "remainingHours", { hours, minutes });
	if (minutes > 0) return t(lang, "remainingMinutes", { minutes });
	return t(lang, "remainingSeconds", { seconds: whole });
}

export type Trend = "up" | "down" | "neutral";

/** Null without a comparable previous period: a neutral arrow would claim "unchanged". */
export function trendOf(current: number, previous: number | null): Trend | null {
	if (previous === null) return null;
	if (current > previous) return "up";
	if (current < previous) return "down";
	return "neutral";
}

/** The comparison under a stat. Growth from zero has no percentage. */
export function comparisonText(current: number, previous: number | null, locale?: string): string {
	const lang = langOf(locale);
	if (previous === null) return t(lang, "noEarlierPeriod");
	if (previous === 0 && current === 0) return t(lang, "noneEitherPeriod");
	if (previous === 0) return t(lang, "upFromNone");
	const ratio = (current - previous) / previous;
	const change = new Intl.NumberFormat(lang, {
		style: "percent",
		signDisplay: "exceptZero",
		maximumFractionDigits: Math.abs(ratio) < 0.01 ? 1 : 0,
	}).format(ratio);
	return t(lang, "vsPrevious", { change });
}

/**
 * A day key the reader's way: "9 Oct 2026". The key is already a local day,
 * so it is formatted as the calendar date it names, which is what
 * `timeZone: "UTC"` does with a key read as UTC midnight.
 */
export function formatDay(day: string, locale?: string): string {
	const ms = Date.parse(`${day}T00:00:00.000Z`);
	if (Number.isNaN(ms)) return day;
	try {
		return new Intl.DateTimeFormat(langOf(locale) === "en" ? "en-AU" : langOf(locale), { dateStyle: "medium", timeZone: "UTC" }).format(ms);
	} catch {
		return day;
	}
}

/** A time in the configured zone, as the day rows count it: "10 Oct 2026, 8:43 am AEDT". */
export function formatTime(iso: string, locale: string | undefined, zone: string): string {
	const ms = Date.parse(iso);
	if (Number.isNaN(ms)) return iso;
	try {
		return new Intl.DateTimeFormat(langOf(locale) === "en" ? "en-AU" : langOf(locale), {
			day: "numeric",
			month: "short",
			year: "numeric",
			hour: "numeric",
			minute: "2-digit",
			timeZone: zone,
			timeZoneName: "short",
		}).format(ms);
	} catch {
		return iso;
	}
}

/**
 * A time for a table cell, short enough not to wrap: "9 Oct 11:54", with
 * the year only when it is not the current one ("9 Oct 2025 11:54"). In
 * the configured zone, 24-hour.
 */
export function formatCompact(at: number | string, locale: string | undefined, zone: string, now: Date): string {
	const ms = typeof at === "number" ? at : Date.parse(at);
	if (Number.isNaN(ms)) return String(at);
	try {
		const lang = langOf(locale) === "en" ? "en-AU" : langOf(locale);
		const year = (v: number) => new Intl.DateTimeFormat("en", { year: "numeric", timeZone: zone }).format(v);
		const date = new Intl.DateTimeFormat(lang, { day: "numeric", month: "short", ...(year(ms) !== year(now.getTime()) && { year: "numeric" }), timeZone: zone }).format(ms);
		const time = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: zone }).format(ms);
		return `${date} ${time}`;
	} catch {
		return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
	}
}

/** A day key as a short chart label: "27 Sept". */
export function formatShortDay(day: string, locale?: string): string {
	const ms = Date.parse(`${day}T00:00:00.000Z`);
	if (Number.isNaN(ms)) return day;
	try {
		return new Intl.DateTimeFormat(langOf(locale) === "en" ? "en-AU" : langOf(locale), { day: "numeric", month: "short", timeZone: "UTC" }).format(ms);
	} catch {
		return day;
	}
}

/** Bytes as "1.7 MB", "820 kB": decimal units, as network counters are read. */
export function formatBytes(bytes: number, locale?: string): string {
	const units = ["B", "kB", "MB", "GB", "TB"];
	let value = Math.max(0, bytes);
	let unit = 0;
	while (value >= 1000 && unit < units.length - 1) {
		value /= 1000;
		unit++;
	}
	const digits = unit === 0 || value >= 100 ? 0 : 1;
	return `${new Intl.NumberFormat(langOf(locale) === "en" ? "en-AU" : langOf(locale), { maximumFractionDigits: digits }).format(value)} ${units[unit]}`;
}

/** A count in short form: "26.5k", "1.2M". */
export function formatShort(value: number, locale?: string): string {
	try {
		return new Intl.NumberFormat(langOf(locale) === "en" ? "en-AU" : langOf(locale), { notation: "compact", maximumFractionDigits: 1 }).format(value);
	} catch {
		return String(Math.round(value));
	}
}

/** The local hour an instant starts, as a chart label: "14:00". */
export function formatHour(ms: number, zone: string): string {
	try {
		return `${new Intl.DateTimeFormat("en-AU", { hour: "2-digit", hourCycle: "h23", timeZone: zone }).format(ms)}:00`;
	} catch {
		return new Date(ms).toISOString().slice(11, 13) + ":00";
	}
}

/** ISO-2 country codes as names in the reader's language, the code where that fails. */
export function countryName(locale: string | undefined): (code: string) => string {
	let names: Intl.DisplayNames | null = null;
	try {
		names = new Intl.DisplayNames([locale ?? "en"], { type: "region" });
	} catch {
		names = null;
	}
	return (code) => {
		if (!code) return "";
		try {
			return names?.of(code) ?? code;
		} catch {
			return code;
		}
	};
}

/** Generated machine ids run to 48 characters: past this, a name shows its first 8 and an ellipsis. */
const LONG_ID = 20;

/**
 * An engine as people read it: its name from the Engine names setting, or
 * its machine id, cut to the first 8 characters when it is a long
 * generated one. The detail view shows the whole id.
 */
export function engineLabel(id: string, names: Record<string, string> | undefined, lang: Lang): string {
	if (!id) return t(lang, "unknown");
	const named = names?.[id];
	if (named) return named;
	return id.length > LONG_ID ? `${id.slice(0, 8)}…` : id;
}
