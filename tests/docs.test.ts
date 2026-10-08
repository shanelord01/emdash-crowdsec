import { describe, expect, it } from "vitest";

import changelog from "../docs/registry/changelog.md?raw";
import description from "../docs/registry/description.md?raw";
import faq from "../docs/registry/faq.md?raw";
import installation from "../docs/registry/installation.md?raw";
import security from "../docs/registry/security.md?raw";
import manifestText from "../emdash-plugin.jsonc?raw";
import readme from "../README.md?raw";
import { BAN_DURATIONS } from "../src/write/actions.js";

/**
 * The documents a site owner reads: the registry page's tabs and the
 * README. Files come in as Vite `?raw` imports, since the suite runs inside
 * workerd.
 */

const FILES: Record<string, string> = {
	"docs/registry/changelog.md": changelog,
	"docs/registry/description.md": description,
	"docs/registry/faq.md": faq,
	"docs/registry/installation.md": installation,
	"docs/registry/security.md": security,
};

/** JSON with comments and trailing commas, as `emdash-plugin.jsonc` is written. */
function parseJsonc(text: string): unknown {
	let out = "";
	for (let i = 0; i < text.length; i++) {
		const c = text[i]!;
		if (c === '"') {
			let j = i + 1;
			while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
			out += text.slice(i, j + 1);
			i = j;
		} else if (c === "/" && text[i + 1] === "/") {
			while (i < text.length && text[i] !== "\n") i++;
			out += "\n";
		} else if (c === "/" && text[i + 1] === "*") {
			i = text.indexOf("*/", i + 2) + 1;
		} else out += c;
	}
	return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

function manifest(): Record<string, unknown> {
	return parseJsonc(manifestText) as Record<string, unknown>;
}

function graphemes(text: string): number {
	let n = 0;
	for (const _ of new Intl.Segmenter("en", { granularity: "grapheme" }).segment(text)) n++;
	return n;
}

describe("the manifest description", () => {
	// The registry refuses one over 140 graphemes, and `emdash-plugin validate` does not check it.
	it("is at most 140 graphemes", () => {
		const text = manifest().description;
		expect(typeof text).toBe("string");
		expect(graphemes(text as string)).toBeLessThanOrEqual(140);
	});
});

describe("the registry page's sections", () => {
	const sections = manifest().sections as Record<string, { file: string }>;

	it("declares all five, each as a file inside the repository", () => {
		expect(Object.keys(sections).sort()).toEqual(["changelog", "description", "faq", "installation", "security"]);
		for (const [key, value] of Object.entries(sections)) {
			expect(value.file, key).toMatch(/^docs\/registry\/[a-z]+\.md$/);
		}
	});

	for (const key of ["description", "installation", "faq", "changelog", "security"]) {
		it(`keeps ${key} inside the registry's caps of 20000 bytes and 2000 graphemes`, () => {
			const text = FILES[sections[key]!.file];
			expect(text, sections[key]!.file).toBeDefined();
			expect(text!.trim().length).toBeGreaterThan(200);
			expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(20_000);
			expect(graphemes(text!)).toBeLessThanOrEqual(2_000);
		});
	}
});

describe("the documents say what the code does", () => {
	const all = [readme, ...Object.values(FILES), manifestText];

	it("name every route the client uses, and the dangerous filter form only as a warning", () => {
		for (const route of [
			"POST /v1/watchers/login",
			"GET /v1/alerts",
			"GET /v1/alerts/{id}",
			"POST /v1/alerts",
			"DELETE /v1/alerts/{id}",
			"DELETE /v1/decisions/{id}",
			"POST /v1/allowlists/check",
		]) {
			expect(readme, route).toContain(route);
			expect(installation, route).toContain(route);
		}
		expect(readme).toMatch(/Never admit `DELETE \/v1\/decisions` without an id/);
		expect(readme).not.toMatch(/allowlists\/check\/\{/);
	});

	it("offer the durations the ban form offers", () => {
		expect(Object.keys(BAN_DURATIONS)).toEqual(["1h", "4h", "24h", "7d", "30d"]);
		expect(readme).toContain("1 hour, 4 hours, 24 hours, 7 days or 30 days");
	});

	it("contain no em or en dashes", () => {
		for (const text of all) expect(text).not.toMatch(/[–—]/);
	});
});
