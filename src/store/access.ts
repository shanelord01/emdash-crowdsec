/**
 * Typed access to the declared storage collections.
 *
 * `PluginContext["storage"]` maps every declared collection to an untyped
 * collection, so the row type is asserted once here instead of through
 * the sync and the pages. A collection missing at runtime (an older
 * manifest) comes back as `null` for the caller to handle, rather than a
 * `TypeError` inside a cron tick that has no retry.
 */

import type { PluginContext } from "emdash/plugin";

import type { AlertRow, DayRow } from "./rows.js";

export interface Page<T> {
	items: Array<{ id: string; data: T }>;
	cursor?: string;
	hasMore: boolean;
}

export interface QuerySpec {
	where?: Record<string, unknown>;
	orderBy?: Record<string, "asc" | "desc">;
	limit?: number;
	cursor?: string;
}

export interface Typed<T> {
	getMany(ids: string[]): Promise<Map<string, T>>;
	putMany(items: Array<{ id: string; data: T }>): Promise<void>;
	deleteMany(ids: string[]): Promise<number>;
	query(spec?: QuerySpec): Promise<Page<T>>;
}

/** Storage clamps a query's `limit` to 100 rows. */
export const BIND_LIMIT = 100;

/**
 * Most ids one `getMany` or `deleteMany` may carry. D1 binds at most 100
 * parameters per statement and storage also binds the plugin id and the
 * collection name, so 98. The wrapper splits every call: a call over 98
 * ids costs one bridge call per slice, which the budget has to count.
 */
export const ID_BATCH = BIND_LIMIT - 2;

export function chunk<T>(items: T[], size: number = ID_BATCH): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
	return out;
}

function wrap<T>(raw: unknown): Typed<T> | null {
	if (!raw || typeof raw !== "object") return null;
	const col = raw as {
		getMany(ids: string[]): Promise<Map<string, unknown>>;
		putMany(items: Array<{ id: string; data: unknown }>): Promise<void>;
		deleteMany(ids: string[]): Promise<number>;
		query(spec?: unknown): Promise<{ items: Array<{ id: string; data: unknown }>; cursor?: string; hasMore: boolean }>;
	};
	return {
		async getMany(ids) {
			const out = new Map<string, T>();
			for (const slice of chunk(ids)) {
				for (const [id, value] of await col.getMany(slice)) out.set(id, value as T);
			}
			return out;
		},
		putMany(items) {
			return col.putMany(items);
		},
		async deleteMany(ids) {
			let deleted = 0;
			for (const slice of chunk(ids)) deleted += await col.deleteMany(slice);
			return deleted;
		},
		async query(spec) {
			return (await col.query(spec)) as Page<T>;
		},
	};
}

export function alertsStore(ctx: PluginContext): Typed<AlertRow> | null {
	return wrap<AlertRow>(ctx.storage?.alerts);
}

export function daysStore(ctx: PluginContext): Typed<DayRow> | null {
	return wrap<DayRow>(ctx.storage?.days);
}
