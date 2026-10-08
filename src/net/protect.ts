/**
 * The addresses a ban must never cover, gathered before any write.
 *
 * Four sources, each named in the refusal so an administrator knows which
 * rule stopped the ban:
 *
 * - **The caller's own address.** The host derives `requestMeta.ip` on
 *   Cloudflare (`CF-Connecting-IP`) and from proxy headers the operator
 *   declared as trusted. Off Cloudflare without that declaration it is
 *   null, so the forwarding headers a reverse proxy sets (`X-Real-IP`,
 *   every `X-Forwarded-For` entry, `CF-Connecting-IP`, `True-Client-IP`)
 *   are read as well. Over-protecting is the safe direction here: these
 *   headers stop a ban, they never allow one.
 * - **The site's addresses**, from the site URL's hostname.
 * - **The LAPI host's addresses**, from the LAPI URL's hostname.
 * - **The Protected addresses setting.**
 *
 * A sandboxed plugin cannot resolve names itself, so hostnames are looked
 * up with DNS over HTTPS at `cloudflare-dns.com` and cached in KV for a
 * day. The sync refreshes the cache in the background while changes are
 * allowed, and the setup check refreshes it too, so a ban rarely finds it
 * cold. When it is cold, the ban looks the names up and asks to be tried
 * again rather than going ahead without the check.
 */

import { failure } from "../i18n.js";
import type { FetchLike } from "../lapi/client.js";
import type { Result } from "../lapi/types.js";
import { USER_AGENT } from "../version.js";
import { parseNetwork, type Network, type ProtectedEntry } from "./ip.js";

export const DNS_KEY = "sync.dns";
export const DNS_TTL_MS = 24 * 3_600_000;
const DOH_URL = "https://cloudflare-dns.com/dns-query";

/** A day's lookups of the hosts in `key`. */
export interface DnsCache {
	at: string;
	/** The hostnames looked up, sorted and joined: other settings mean another lookup. */
	key: string;
	addresses: Record<string, string[]>;
}

const CALLER_HEADERS = ["x-real-ip", "x-forwarded-for", "cf-connecting-ip", "true-client-ip"];

/**
 * Every address the request could have come from: the host's `requestMeta.ip`
 * and the forwarding headers. Entries that are not addresses are dropped.
 */
export function callerAddresses(routeCtx: { requestMeta?: unknown; request?: { headers?: Record<string, string> } }): string[] {
	const found = new Set<string>();
	const meta = routeCtx.requestMeta as { ip?: unknown } | undefined;
	const add = (value: unknown) => {
		if (typeof value !== "string") return;
		for (const part of value.split(",")) {
			const text = withoutPort(part.trim());
			const net = parseNetwork(text);
			if (net && (net.prefix === 32 || net.prefix === 128)) found.add(text);
		}
	};
	add(meta?.ip);
	const headers = routeCtx.request?.headers ?? {};
	for (const [name, value] of Object.entries(headers)) {
		if (CALLER_HEADERS.includes(name.toLowerCase())) add(value);
	}
	return [...found];
}

/**
 * An address from a forwarding header without its port: `203.0.113.5:4711`
 * and `[2001:db8::1]:443` become `203.0.113.5` and `2001:db8::1`. A bare
 * IPv6 address has several colons and is left as it is.
 */
export function withoutPort(text: string): string {
	const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
	if (bracketed) return bracketed[1]!;
	const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(text);
	if (v4) return v4[1]!;
	return text;
}

/**
 * A name DNS over HTTPS cannot answer: `localhost`, a name without a dot,
 * or one under `.local`, `.localhost` or `.internal`.
 */
export function isLocalName(name: string): boolean {
	return name === "localhost" || !name.includes(".") || /\.(local|localhost|internal)$/.test(name);
}

/** The hostname of a URL, or null. An address literal is returned as the address. */
export function hostOf(url: string): string | null {
	try {
		const host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
		return host || null;
	} catch {
		return null;
	}
}

/** The names that need a lookup: the site's and the LAPI's hostnames that are not address literals. */
export function namesToResolve(siteUrl: string, lapiUrl: string): string[] {
	const names = new Set<string>();
	for (const url of [siteUrl, lapiUrl]) {
		const host = hostOf(url);
		if (host && !parseNetwork(host)) names.add(host);
	}
	return [...names].sort();
}

export function dnsFresh(cache: DnsCache | null | undefined, names: string[], now: Date): cache is DnsCache {
	return Boolean(cache && cache.key === names.join(",") && now.getTime() - Date.parse(cache.at) < DNS_TTL_MS);
}

/**
 * Look the names up, A and AAAA each: two requests per name. Answers with
 * no address (an AAAA-less host) are fine, but a name with no address at all
 * fails, since a ban could then cover the site without anyone knowing.
 */
export async function resolveNames(fetch: FetchLike, names: string[], now: Date): Promise<Result<DnsCache> & { requests: number }> {
	const addresses: Record<string, string[]> = {};
	let requests = 0;
	for (const name of names) {
		const found: string[] = [];
		for (const type of ["A", "AAAA"] as const) {
			requests++;
			let body: unknown;
			try {
				const response = await fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`, {
					headers: { Accept: "application/dns-json", "User-Agent": USER_AGENT },
					redirect: "manual",
				});
				if (!response.ok) return { ...failure("dnsFailed", { name, detail: `HTTP ${response.status}` }), requests };
				body = await response.json();
			} catch (error) {
				return { ...failure("dnsFailed", { name, detail: error instanceof Error ? error.message : String(error) }), requests };
			}
			const answers = (body as { Answer?: Array<{ type?: number; data?: unknown }> } | null)?.Answer ?? [];
			for (const answer of answers) {
				if ((answer.type === 1 || answer.type === 28) && typeof answer.data === "string" && parseNetwork(answer.data)) {
					found.push(answer.data);
				}
			}
		}
		if (found.length === 0) return { ...failure("dnsEmpty", { name }), requests };
		addresses[name] = [...new Set(found)];
	}
	return { ok: true, value: { at: now.toISOString(), key: names.join(","), addresses }, requests };
}

/** Everything a ban must not cover, each entry tagged with the rule that protects it. */
export function protections(opts: {
	callers: string[];
	siteUrl: string;
	lapiUrl: string;
	dns: DnsCache | null;
	setting: Network[];
}): ProtectedEntry[] {
	const out: ProtectedEntry[] = [];
	const push = (text: string, rule: ProtectedEntry["rule"]) => {
		const network = parseNetwork(text);
		if (network) out.push({ network, rule });
	};
	for (const address of opts.callers) push(address, "caller");
	for (const [url, rule] of [
		[opts.siteUrl, "site"],
		[opts.lapiUrl, "lapi"],
	] as const) {
		const host = hostOf(url);
		if (!host) continue;
		if (parseNetwork(host)) push(host, rule);
		else for (const address of opts.dns?.addresses[host] ?? []) push(address, rule);
	}
	for (const network of opts.setting) out.push({ network, rule: "setting" });
	return out;
}
