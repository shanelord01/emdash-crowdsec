import { describe, expect, it } from "vitest";

import pkg from "../package.json?raw";
import { USER_AGENT, VERSION } from "../src/version.js";

describe("the version", () => {
	it("is the package's, and the User-Agent carries it as LAPI wants: name/version", () => {
		expect(VERSION).toBe((JSON.parse(pkg) as { version: string }).version);
		expect(USER_AGENT).toBe(`emdash-crowdsec/${VERSION}`);
	});
});
