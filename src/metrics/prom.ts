/**
 * The Prometheus text format, parsed by hand. Pure.
 *
 * Only the series the traffic charts use are kept. Histograms, summaries
 * and everything else are skipped line by line, so a 100 KB answer costs
 * no more memory than the handful of numbers it yields.
 */

export interface Series {
	name: string;
	labels: Record<string, string>;
	value: number;
}

/** The series the plugin reads, from the security engine and the firewall bouncer. */
export const KEPT_SERIES = new Set([
	"fw_bouncer_dropped_packets",
	"fw_bouncer_dropped_bytes",
	"fw_bouncer_processed_packets",
	"fw_bouncer_processed_bytes",
	"fw_bouncer_banned_ips",
	"cs_active_decisions",
	"cs_appsec_reqs_total",
	"cs_appsec_block_total",
	"cs_appsec_challenge_requested_total",
	"cs_appsec_challenge_submitted_total",
	"cs_appsec_challenge_accepted_total",
	"cs_appsec_challenge_rejected_total",
	"cs_appsec_challenge_exempt_total",
	"cs_parser_hits_total",
]);

const NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*/;

/** Every kept sample in a Prometheus text answer. Lines that do not parse are skipped. */
export function parsePrometheus(text: string, kept: Set<string> = KEPT_SERIES): Series[] {
	const out: Series[] = [];
	for (const raw of text.split("\n")) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const name = NAME.exec(line)?.[0];
		if (!name || !kept.has(name)) continue;
		let rest = line.slice(name.length);
		let labels: Record<string, string> = {};
		if (rest.startsWith("{")) {
			const parsed = parseLabels(rest);
			if (!parsed) continue;
			labels = parsed.labels;
			rest = rest.slice(parsed.length);
		}
		const value = parseValue(rest.trim().split(/\s+/)[0] ?? "");
		if (value === null) continue;
		out.push({ name, labels, value });
	}
	return out;
}

/** `{a="x",b="y\"z"}` from the start of `text`, and how many characters it took. */
function parseLabels(text: string): { labels: Record<string, string>; length: number } | null {
	const labels: Record<string, string> = {};
	let i = 1;
	while (i < text.length) {
		while (text[i] === " " || text[i] === ",") i++;
		if (text[i] === "}") return { labels, length: i + 1 };
		const key = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(text.slice(i))?.[0];
		if (!key || text[i + key.length] !== "=" || text[i + key.length + 1] !== '"') return null;
		i += key.length + 2;
		let value = "";
		while (i < text.length && text[i] !== '"') {
			if (text[i] === "\\") {
				const next = text[i + 1];
				value += next === "n" ? "\n" : (next ?? "");
				i += 2;
			} else {
				value += text[i];
				i++;
			}
		}
		if (text[i] !== '"') return null;
		labels[key] = value;
		i++;
	}
	return null;
}

function parseValue(text: string): number | null {
	if (text === "+Inf" || text === "-Inf" || text === "NaN" || !text) return null;
	const n = Number(text);
	return Number.isFinite(n) ? n : null;
}
