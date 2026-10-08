import type { PluginContext } from "emdash/plugin";

/**
 * An in-memory `PluginContext` for the sync's own logic, where the test
 * needs to act between two of the plugin's calls: another tick claiming the
 * state mid-run, or LAPI answering one search and refusing the next. KV
 * revisions behave as EmDash's do: every write makes a new one, and a
 * conditional write against an old one is not applied.
 */

type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export function fakeCtx(opts: { settings: Record<string, unknown>; fetch?: Fetch; siteUrl?: string; onPut?: (collection: string) => void }) {
	const kv = new Map<string, { value: unknown; rev: number }>();
	let rev = 0;
	const scheduled: Array<{ name: string; schedule: string }> = [];
	const requests: string[] = [];
	const stores = new Map<string, Map<string, unknown>>();

	const collection = (name: string) => {
		const rows = stores.get(name) ?? new Map<string, unknown>();
		stores.set(name, rows);
		return {
			async getMany(ids: string[]) {
				return new Map(ids.filter((id) => rows.has(id)).map((id) => [id, rows.get(id)]));
			},
			async putMany(items: Array<{ id: string; data: unknown }>) {
				for (const item of items) rows.set(item.id, item.data);
				opts.onPut?.(name);
			},
			async deleteMany(ids: string[]) {
				let n = 0;
				for (const id of ids) if (rows.delete(id)) n++;
				return n;
			},
			async query(spec?: { limit?: number }) {
				const items = [...rows.entries()].slice(0, spec?.limit ?? 100).map(([id, data]) => ({ id, data }));
				return { items, hasMore: rows.size > items.length };
			},
		};
	};

	const ctx = {
		site: { url: opts.siteUrl ?? "https://www.example.test", name: "Test", locale: "en" },
		kv: {
			async get(key: string) {
				return kv.get(key)?.value ?? null;
			},
			async getVersioned(key: string) {
				const entry = kv.get(key);
				return entry ? { value: entry.value, revision: String(entry.rev) } : null;
			},
			async compareAndSet(key: string, expected: string | null, value: unknown) {
				const entry = kv.get(key);
				if ((entry ? String(entry.rev) : null) !== expected) return { applied: false };
				kv.set(key, { value, rev: ++rev });
				return { applied: true, revision: String(rev) };
			},
			async set(key: string, value: unknown) {
				kv.set(key, { value, rev: ++rev });
			},
			async delete(key: string) {
				return kv.delete(key);
			},
			async list(prefix = "") {
				return [...kv.entries()].filter(([key]) => key.startsWith(prefix)).map(([key, entry]) => ({ key, value: entry.value }));
			},
		},
		settings: {
			async list() {
				return Object.entries(opts.settings).map(([key, value]) => ({ key, value }));
			},
		},
		storage: { alerts: collection("alerts"), days: collection("days") },
		cron: {
			async schedule(name: string, o: { schedule: string }) {
				scheduled.push({ name, schedule: o.schedule });
			},
		},
		http: {
			async fetch(url: string, init?: RequestInit) {
				requests.push(url);
				if (!opts.fetch) throw new Error(`no fetch for ${url}`);
				return await opts.fetch(url, init);
			},
		},
	};

	return {
		ctx: ctx as unknown as PluginContext,
		scheduled,
		requests,
		rows: (name: string) => stores.get(name) ?? new Map(),
		state: () => kv.get("sync.state")?.value as Record<string, any> | undefined,
		/** Write the state as another tick would, with a new revision. */
		setState: (value: unknown) => kv.set("sync.state", { value, rev: ++rev }),
	};
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
