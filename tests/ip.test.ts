import { describe, expect, it } from "vitest";

import { checkBanTarget, embeddedV4, formatNetwork, hostBitsOf, parseNetwork, parseNetworkList, sameNetwork, type ProtectedEntry } from "../src/net/ip.js";
import { callerAddresses, protections } from "../src/net/protect.js";

const entry = (text: string, rule: ProtectedEntry["rule"]): ProtectedEntry => ({ network: parseNetwork(text)!, rule });

describe("parsing", () => {
	it("reads addresses and ranges and writes them canonically", () => {
		expect(formatNetwork(parseNetwork("203.0.113.7")!)).toBe("203.0.113.7");
		expect(formatNetwork(parseNetwork("203.0.113.0/24")!)).toBe("203.0.113.0/24");
		expect(formatNetwork(parseNetwork("2001:DB8:0:0:0:0:0:1")!)).toBe("2001:db8::1");
		expect(formatNetwork(parseNetwork("2001:db8:1::/48")!)).toBe("2001:db8:1::/48");
		expect(formatNetwork(parseNetwork("::ffff:203.0.113.7")!)).toBe("::ffff:203.0.113.7");
	});

	it("refuses what is not an address", () => {
		for (const text of ["", "203.0.113", "203.0.113.256", "1.2.3.4/33", "2001:db8::1::2", "fe80::1%eth0", "example.com", "203.0.113.7/24/1", "1.2.3.4 OR 1=1", "01.2.3.4"]) {
			expect(parseNetwork(text), text).toBeNull();
		}
	});

	it("is strict: no host bits after the prefix, no leading-zero prefix, no IPv4 part before ::", () => {
		expect(parseNetwork("1.2.3.4/16")).toBeNull();
		expect(hostBitsOf("1.2.3.4/16")).toBe("1.2.0.0/16");
		expect(parseNetwork("1.2.0.0/016")).toBeNull();
		expect(parseNetwork("1.2.3.4::")).toBeNull();
		expect(parseNetwork("1.2.3.4::1")).toBeNull();
		expect(parseNetwork("::ffff:1.2.3.4")).not.toBeNull();
		expect(checkBanTarget("203.0.113.7/24", [])).toMatchObject({ ok: false, reason: "m7v", meant: "203.0.113.0/24" });
	});

	it("compares address text by value", () => {
		expect(sameNetwork("2001:db8::1", "2001:0db8:0000::1")).toBe(true);
		expect(sameNetwork("203.0.113.7", "::ffff:203.0.113.7")).toBe(true);
		expect(sameNetwork("203.0.113.7", "203.0.113.8")).toBe(false);
	});

	it("splits the Protected addresses setting and keeps the entries that are not addresses apart", () => {
		const { networks, invalid } = parseNetworkList("198.51.100.4, 2001:db8::/64\nnot-an-ip");
		expect(networks.map(formatNetwork)).toEqual(["198.51.100.4", "2001:db8::/64"]);
		expect(invalid).toEqual(["not-an-ip"]);
	});
});

describe("ban targets", () => {
	it("accepts a public address and a /16 or /48 range", () => {
		expect(checkBanTarget("203.0.113.7", [])).toMatchObject({ ok: true, value: "203.0.113.7", scope: "Ip" });
		expect(checkBanTarget("203.0.0.0/16", [])).toMatchObject({ ok: true, scope: "Range" });
		expect(checkBanTarget("2a00:1450:4000::/48", [])).toMatchObject({ ok: true, scope: "Range" });
	});

	it("refuses ranges wider than /16 for IPv4 and /48 for IPv6, the whole internet included", () => {
		expect(checkBanTarget("203.0.0.0/15", [])).toMatchObject({ ok: false, reason: "m7r" });
		expect(checkBanTarget("2a00:1450::/47", [])).toMatchObject({ ok: false, reason: "m7r" });
		expect(checkBanTarget("0.0.0.0/0", [])).toMatchObject({ ok: false, reason: "m7r" });
		expect(checkBanTarget("::/0", [])).toMatchObject({ ok: false, reason: "m7r" });
	});

	it("refuses private, loopback, link-local, CGNAT, multicast and unspecified space", () => {
		for (const text of [
			"10.1.2.3",
			"172.16.5.4",
			"192.168.1.1",
			"127.0.0.1",
			"169.254.1.1",
			"100.64.0.1",
			"100.101.102.103", // Tailscale
			"224.0.0.1",
			"0.0.0.0",
			"::1",
			"::",
			"fe80::1",
			"fd12:3456::1",
			"ff02::1",
		]) {
			expect(checkBanTarget(text, []), text).toMatchObject({ ok: false, reason: "m7s" });
		}
	});

	it("refuses a range that only partly overlaps reserved space", () => {
		expect(checkBanTarget("100.64.0.0/16", [])).toMatchObject({ ok: false, reason: "m7s" });
	});

	it("names the rule that protects an address: the caller's, the site's, the LAPI host's, the setting's", () => {
		const list = [entry("198.51.100.7", "caller"), entry("198.51.100.10", "site"), entry("198.51.100.20", "lapi"), entry("192.0.2.0/24", "setting")];
		expect(checkBanTarget("198.51.100.7", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("198.51.100.10", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "site" });
		expect(checkBanTarget("198.51.100.20", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "lapi" });
		expect(checkBanTarget("192.0.2.77", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "setting", match: "192.0.2.0/24" });
	});

	it("refuses a range that contains a protected address", () => {
		const list = [entry("198.51.100.7", "caller")];
		expect(checkBanTarget("198.51.0.0/16", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("198.52.0.0/16", list)).toMatchObject({ ok: true });
	});

	it("checks an IPv4-mapped IPv6 address as the IPv4 address it maps", () => {
		const list = [entry("198.51.100.7", "caller")];
		expect(checkBanTarget("::ffff:198.51.100.7", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("::ffff:c633:6407", list)).toMatchObject({ ok: false, reason: "protectedAddress" });
		expect(checkBanTarget("::ffff:10.0.0.1", [])).toMatchObject({ ok: false, reason: "m7s" });
		expect(checkBanTarget("::ffff:0:0/96", [])).toMatchObject({ ok: false, reason: "m7r" });
		// An IPv6 range that covers the whole mapped block is refused as well.
		expect(checkBanTarget("::/64", [])).toMatchObject({ ok: false, reason: "m7s" });
		// A protected entry written in mapped form protects the IPv4 address too.
		expect(checkBanTarget("198.51.100.8", [entry("::ffff:198.51.100.8", "setting")])).toMatchObject({ ok: false, rule: "setting" });
		// An allowed mapped address is sent to LAPI as plain IPv4.
		expect(checkBanTarget("::ffff:203.0.113.9", [])).toMatchObject({ ok: true, value: "203.0.113.9" });
	});
});

describe("IPv6 blocks that carry an IPv4 address", () => {
	it("reads the IPv4 address inside NAT64 and 6to4 values", () => {
		expect(formatNetwork(embeddedV4(parseNetwork("64:ff9b::c633:6407")!)!)).toBe("198.51.100.7");
		expect(formatNetwork(embeddedV4(parseNetwork("2002:c633:6407::1")!)!)).toBe("198.51.100.7");
		expect(formatNetwork(embeddedV4(parseNetwork("2002:c633:6407::/48")!)!)).toBe("198.51.100.7");
		expect(embeddedV4(parseNetwork("2001:db8::1")!)).toBeNull();
	});

	it("holds NAT64 and 6to4 values to the IPv4 rules", () => {
		const list = [entry("198.51.100.7", "caller")];
		expect(checkBanTarget("64:ff9b::c633:6407", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("2002:c633:6407::1", list)).toMatchObject({ ok: false, reason: "protectedAddress", rule: "caller" });
		expect(checkBanTarget("64:ff9b::a00:1", [])).toMatchObject({ ok: false, reason: "m7s" }); // 10.0.0.1
		expect(checkBanTarget("2002:c0a8:101::/48", [])).toMatchObject({ ok: false, reason: "m7s" }); // 192.168.1.1
		expect(checkBanTarget("64:ff9b::/100", [])).toMatchObject({ ok: false, reason: "m7r" }); // a /4 of IPv4
		expect(checkBanTarget("2002:cb00:7107::1", [])).toMatchObject({ ok: true }); // 203.0.113.7
	});

	it("refuses the deprecated IPv4-compatible block", () => {
		expect(checkBanTarget("::cb00:7107", [])).toMatchObject({ ok: false, reason: "m7s" });
	});
});

describe("the protected set", () => {
	it("takes the caller from the host's requestMeta and every forwarding header", () => {
		expect(
			callerAddresses({
				requestMeta: { ip: "198.51.100.1" },
				request: { headers: { "x-real-ip": "198.51.100.2", "x-forwarded-for": "198.51.100.3, 10.0.0.1, not-an-ip", "cf-connecting-ip": "2001:db8::5" } },
			}).sort(),
		).toEqual(["10.0.0.1", "198.51.100.1", "198.51.100.2", "198.51.100.3", "2001:db8::5"]);
		expect(callerAddresses({ request: { headers: {} } })).toEqual([]);
	});

	it("adds the site's and the LAPI's looked-up addresses, and address literals without a lookup", () => {
		const list = protections({
			callers: [],
			siteUrl: "https://www.example.test",
			lapiUrl: "https://198.51.100.30/lapi",
			dns: { at: "", key: "", addresses: { "www.example.test": ["198.51.100.10", "2001:db8::10"] } },
			setting: [],
		});
		expect(list.map((e) => `${e.rule}:${formatNetwork(e.network)}`)).toEqual(["site:198.51.100.10", "site:2001:db8::10", "lapi:198.51.100.30"]);
	});
});
