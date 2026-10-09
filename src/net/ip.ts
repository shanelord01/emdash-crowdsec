/**
 * IPv4 and IPv6 addresses and ranges, parsed by hand. Pure.
 *
 * Every address the plugin sends to LAPI in a write passes through here
 * first: a ban on a private range, on the operator's own address or on
 * half the internet is refused before any request is made. The same
 * parser checks the address an agent asks about, so nothing but an
 * address ever reaches a query string.
 */

export type Family = 4 | 6;

/** A network: an address with a prefix length. A single address is /32 or /128. */
export interface Network {
	family: Family;
	base: bigint;
	prefix: number;
}

const BITS: Record<Family, number> = { 4: 32, 6: 128 };

/** The narrowest prefix a ban may cover: a /16 of IPv4, a /48 of IPv6. */
export const WIDEST_PREFIX: Record<Family, number> = { 4: 16, 6: 48 };

const V4_PART = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const V6_GROUP = /^[0-9a-f]{1,4}$/;

function parseV4(text: string): bigint | null {
	const parts = text.split(".");
	if (parts.length !== 4 || !parts.every((part) => V4_PART.test(part))) return null;
	return parts.reduce((acc, part) => (acc << 8n) | BigInt(Number(part)), 0n);
}

function parseV6(input: string): bigint | null {
	const text = input.toLowerCase();
	if (!text || text.includes("%")) return null;
	const halves = text.split("::");
	if (halves.length > 2) return null;

	// A dotted IPv4 part may only end the whole address: `::ffff:1.2.3.4`,
	// never `1.2.3.4::`.
	const groupsOf = (part: string, last: boolean): number[] | null => {
		if (part === "") return [];
		const out: number[] = [];
		const pieces = part.split(":");
		for (const [index, piece] of pieces.entries()) {
			if (last && index === pieces.length - 1 && piece.includes(".")) {
				const v4 = parseV4(piece);
				if (v4 === null) return null;
				out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
				continue;
			}
			if (!V6_GROUP.test(piece)) return null;
			out.push(parseInt(piece, 16));
		}
		return out;
	};

	const head = groupsOf(halves[0]!, halves.length === 1);
	const tail = halves.length === 2 ? groupsOf(halves[1]!, true) : [];
	if (!head || !tail) return null;
	let groups: number[];
	if (halves.length === 2) {
		const fill = 8 - head.length - tail.length;
		if (fill < 1) return null;
		groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
	} else {
		groups = head;
	}
	if (groups.length !== 8) return null;
	return groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
}

function maskOf(family: Family, prefix: number): bigint {
	const bits = BigInt(BITS[family]);
	const all = (1n << bits) - 1n;
	return prefix === 0 ? 0n : (all >> (bits - BigInt(prefix))) << (bits - BigInt(prefix));
}

/**
 * An address or a CIDR range, or null when it is neither. Strict: a range
 * with bits set after its prefix (`10.1.2.3/16`) and a prefix with a
 * leading zero (`/016`) are refused rather than quietly rewritten, so what
 * is banned is exactly what was typed. `hostBitsOf` names the fix.
 */
export function parseNetwork(input: unknown): Network | null {
	const net = parseLoose(input);
	if (!net || (net.base & ~maskOf(net.family, net.prefix) & ((1n << BigInt(BITS[net.family])) - 1n)) !== 0n) return null;
	return net;
}

/** The range a CIDR with host bits set was probably meant as, or null when the text is not that mistake. */
export function hostBitsOf(input: unknown): string | null {
	if (parseNetwork(input)) return null;
	const net = parseLoose(input);
	if (!net) return null;
	return formatNetwork({ ...net, base: net.base & maskOf(net.family, net.prefix) });
}

function parseLoose(input: unknown): Network | null {
	if (typeof input !== "string") return null;
	const text = input.trim();
	if (!text || text.length > 64) return null;
	const [address, prefixText, extra] = text.split("/");
	if (extra !== undefined || !address) return null;

	const v4 = parseV4(address);
	const family: Family | null = v4 !== null ? 4 : address.includes(":") ? 6 : null;
	if (family === null) return null;
	const value = v4 ?? parseV6(address);
	if (value === null) return null;

	let prefix = BITS[family];
	if (prefixText !== undefined) {
		if (!/^(0|[1-9]\d{0,2})$/.test(prefixText)) return null;
		prefix = Number(prefixText);
		if (prefix > BITS[family]) return null;
	}
	return { family, base: value, prefix };
}

export function isSingleAddress(net: Network): boolean {
	return net.prefix === BITS[net.family];
}

function within(a: Network, b: Network): boolean {
	return a.family === b.family && a.prefix >= b.prefix && (a.base & maskOf(b.family, b.prefix)) === b.base;
}

function sameFamilyOverlap(a: Network, b: Network): boolean {
	if (a.family !== b.family) return false;
	const mask = maskOf(a.family, Math.min(a.prefix, b.prefix));
	return (a.base & mask) === (b.base & mask);
}

/** IPv6 blocks that carry an IPv4 address: mapped, SIIT translated, NAT64 and 6to4. */
const MAPPED = { family: 6, base: 0xffffn << 32n, prefix: 96 } as Network;
const SIIT = { family: 6, base: 0xffffn << 48n, prefix: 96 } as Network;
const NAT64 = { family: 6, base: 0x64ff9bn << 96n, prefix: 96 } as Network;
const SIX_TO_FOUR = { family: 6, base: 0x2002n << 112n, prefix: 16 } as Network;
export const TRANSLATION_BLOCKS: Network[] = [MAPPED, SIIT, NAT64, SIX_TO_FOUR];

/**
 * The IPv4 network an IPv6 one carries, when it lies inside a mapped
 * (`::ffff:0:0/96`), SIIT translated (`::ffff:0:0:0/96`), NAT64
 * (`64:ff9b::/96`) or 6to4 (`2002::/16`) block, or null. A rule written
 * for an IPv4 address then applies to it too.
 */
export function embeddedV4(net: Network): Network | null {
	if (net.family !== 6) return null;
	if (within(net, MAPPED) || within(net, SIIT) || within(net, NAT64)) {
		return { family: 4, base: net.base & 0xffffffffn, prefix: net.prefix - 96 };
	}
	if (within(net, SIX_TO_FOUR)) {
		return { family: 4, base: (net.base >> 80n) & 0xffffffffn, prefix: Math.min(net.prefix - 16, 32) };
	}
	return null;
}

/** A network and the IPv4 network it carries, if any. */
function forms(net: Network): Network[] {
	const v4 = embeddedV4(net);
	return v4 ? [net, v4] : [net];
}

/** True when the two networks share at least one address, counting the IPv4 address an IPv6 one carries. */
export function overlaps(a: Network, b: Network): boolean {
	return forms(a).some((x) => forms(b).some((y) => sameFamilyOverlap(x, y)));
}

/** `::ffff:a.b.c.d/n` as `a.b.c.d/(n-96)`, anything else unchanged. */
function unmapped(net: Network): Network {
	return within(net, MAPPED) ? { family: 4, base: net.base & 0xffffffffn, prefix: net.prefix - 96 } : net;
}

/**
 * True when `inner` lies inside `outer`, reading an IPv4-mapped form
 * (`::ffff:a.b.c.d`) on either side as its IPv4 address. NAT64, SIIT and
 * 6to4 forms are other addresses on the wire, so they do not match an IPv4
 * filter.
 */
export function contains(outer: Network, inner: Network): boolean {
	return within(unmapped(inner), unmapped(outer));
}

/** The canonical text LAPI is sent: dotted IPv4, RFC 5952 IPv6, `/n` only for a range. */
export function formatNetwork(net: Network): string {
	const address = net.family === 4 ? formatV4(net.base) : formatV6(net.base);
	return isSingleAddress(net) ? address : `${address}/${net.prefix}`;
}

function formatV4(value: bigint): string {
	return [24n, 16n, 8n, 0n].map((shift) => String(Number((value >> shift) & 0xffn))).join(".");
}

function formatV6(value: bigint): string {
	const groups = Array.from({ length: 8 }, (_, i) => Number((value >> BigInt((7 - i) * 16)) & 0xffffn));
	if (value >> 32n === 0xffffn) return `::ffff:${formatV4(value & 0xffffffffn)}`;

	// The longest run of two or more zero groups becomes "::", the first one on a tie.
	let bestStart = -1;
	let bestLength = 1;
	for (let i = 0; i < 8; ) {
		if (groups[i] !== 0) {
			i++;
			continue;
		}
		let j = i;
		while (j < 8 && groups[j] === 0) j++;
		if (j - i > bestLength) {
			bestStart = i;
			bestLength = j - i;
		}
		i = j;
	}
	const hex = groups.map((group) => group.toString(16));
	if (bestStart < 0) return hex.join(":");
	return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
}

const RESERVED_TEXT = [
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/96", // IPv4-compatible, deprecated, and :: and ::1 with it
	"64:ff9b:1::/48", // local-use NAT64, which places its IPv4 address by its own prefix length
	"2001::/32", // Teredo, whose IPv4 addresses are obscured
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
];

/** Unspecified, loopback, private, CGNAT, link-local, multicast and reserved space. */
export const RESERVED: Network[] = RESERVED_TEXT.map((text) => parseNetwork(text)!);

/** Why an address is protected: the caller's own, the site's, the LAPI host's or the setting. */
export type ProtectRule = "caller" | "site" | "lapi" | "setting";

export interface ProtectedEntry {
	network: Network;
	rule: ProtectRule;
}

export type TargetRefusal =
	| { reason: "m7n" }
	| { reason: "m7v"; meant: string }
	| { reason: "m7r"; widest: string }
	| { reason: "m7s" }
	| { reason: "protectedAddress"; rule: ProtectRule; match: string };

export type TargetCheck =
	| { ok: true; network: Network; value: string; scope: "Ip" | "Range" }
	| ({ ok: false } & TargetRefusal);

/**
 * May this address or range be banned? A target is refused when it is not
 * an address, is wider than `WIDEST_PREFIX`, touches reserved space, or
 * overlaps any protected entry. An IPv4-mapped IPv6 target is judged as the
 * IPv4 address it maps, so `::ffff:a.b.c.d` cannot slip past a rule.
 */
export function checkBanTarget(input: unknown, protectedList: ProtectedEntry[]): TargetCheck {
	const network = parseNetwork(input);
	if (!network) {
		const meant = hostBitsOf(input);
		return meant ? { ok: false, reason: "m7v", meant } : { ok: false, reason: "m7n" };
	}
	const target = unmapped(network);
	for (const form of forms(target)) {
		if (form.prefix < WIDEST_PREFIX[form.family]) return { ok: false, reason: "m7r", widest: `/${WIDEST_PREFIX[form.family]}` };
	}
	// A range that covers a whole translation block, or reaches past one,
	// would ban IPv4 space no IPv4 rule saw.
	if (TRANSLATION_BLOCKS.some((block) => sameFamilyOverlap(target, block) && !within(target, block))) {
		return { ok: false, reason: "m7s" };
	}
	if (RESERVED.some((reserved) => overlaps(target, reserved))) return { ok: false, reason: "m7s" };
	const hit = protectedList.find((entry) => overlaps(target, entry.network));
	if (hit) return { ok: false, reason: "protectedAddress", rule: hit.rule, match: formatNetwork(unmapped(hit.network)) };
	return { ok: true, network: target, value: formatNetwork(target), scope: isSingleAddress(target) ? "Ip" : "Range" };
}

/** A network in the form shown to people, IPv4-mapped addresses as IPv4. */
export function displayNetwork(net: Network): string {
	return formatNetwork(unmapped(net));
}

/** The protected addresses setting: comma or whitespace separated. Entries that do not parse are returned apart. */
export function parseNetworkList(raw: unknown): { networks: Network[]; invalid: string[] } {
	const networks: Network[] = [];
	const invalid: string[] = [];
	if (typeof raw !== "string") return { networks, invalid };
	for (const part of raw.split(/[\s,]+/)) {
		if (!part) continue;
		const network = parseNetwork(part);
		if (network) networks.push(unmapped(network));
		else invalid.push(part);
	}
	return { networks, invalid };
}

/** Are two pieces of address text the same address or range? */
export function sameNetwork(a: unknown, b: unknown): boolean {
	const x = parseNetwork(a);
	const y = parseNetwork(b);
	if (!x || !y) return false;
	const p = unmapped(x);
	const q = unmapped(y);
	return p.family === q.family && p.prefix === q.prefix && p.base === q.base;
}
