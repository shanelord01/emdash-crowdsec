/**
 * The MCP tool declarations.
 *
 * Only `src/plugin.ts` references `mcpTools()`, from its `mcp` property,
 * which the plugin build strips from the runtime: the schemas end up in the
 * manifest as JSON Schema, and neither zod nor this module ships in the
 * bundle. A schema imported by a route handler would pull zod back in.
 *
 * Output schemas become strict JSON Schema (`additionalProperties: false`)
 * that the MCP server checks every answer against, so each one matches its
 * loader's result type in `./load.ts` key for key. `tests/tools.test.ts`
 * holds the answers against the schemas the build wrote.
 *
 * A tool's permission is its route's: the read tools sit on `plugins:read`
 * routes, the write tools on `plugins:manage` ones.
 */

import type { SandboxedMcpTool } from "emdash/plugin";
import { z } from "zod";

import { BAN_DURATIONS, MAX_NOTE } from "../write/actions.js";
import { BEHAVIOURS } from "../explorer/behaviour.js";
import { DIMENSIONS } from "../explorer/model.js";
import { EXPLORER_PERIODS, MAX_DECISIONS, MAX_GROUPS, MAX_TOP, TOOL_ROUTES } from "./load.js";

export function mcpTools(): Record<string, SandboxedMcpTool> {
	const day = z.string().describe("A day in the plugin's Time zone setting, YYYY-MM-DD.");
	const window = z.object({
		days: z.number().int(),
		since: day,
		until: day.describe("Today in the plugin's time zone. Its numbers still move."),
		partial: z.boolean().describe("True when stored history starts after since, so the numbers cover fewer days than the window."),
	});
	const days = z
		.union([z.literal(7), z.literal(30), z.literal(90)])
		.optional()
		.describe("Window in days, ending today in the plugin's time zone. Default 30.");
	const kinds = z.object({
		waf: z.number().describe("AppSec rules and virtual patches."),
		bot: z.number().describe("The AppSec bot challenge."),
		behaviour: z.number().describe("Log-behaviour scenarios such as probing and brute force."),
		manual: z.number().describe("Bans added by hand."),
	});
	const lastSync = z.string().nullable().describe("When the plugin last synced from CrowdSec, ISO 8601.");
	const ranking = z.array(z.object({ value: z.string(), alerts: z.number() }));
	const origins = z
		.object({ community: z.number(), detections: z.number(), manual: z.number(), other: z.number() })
		.describe("community: the CrowdSec community blocklist and lists. detections: the site's own scenarios and AppSec. manual: bans added by hand.");
	const address = z.string().min(2).max(64).describe("An IPv4 or IPv6 address, or a CIDR range.");
	const writeOutput = z.object({
		done: z.boolean(),
		message: z.string().describe("One sentence: what was done, or which rule refused it and why."),
		value: z.string().optional().describe("The address or range as sent to CrowdSec."),
		alertId: z.string().optional(),
		clientAddressChecked: z
			.boolean()
			.optional()
			.describe(
				"Whether the ban was checked against the address this MCP client connects from. That is the client's egress, which may be a server or a proxy rather than the person's own connection. False when the request carried no address.",
			),
		removed: z.number().optional(),
		remaining: z.number().optional().describe("Active decisions on the address still to remove: call again."),
	});

	return {
		security_summary: {
			description:
				"CrowdSec alerts on this site over the last 7, 30 or 90 days: totals by kind, decisions and bans issued, the period before for comparison, the last 24 hours against the 24 before, and the active ban count. " +
				"From the plugin's stored data (lastSync). previous is null when stored history does not reach back far enough to compare. " +
				"activeBans is the count from the plugin's last read, with its time.",
			route: TOOL_ROUTES.summary,
			input: z.object({ days }),
			output: z.object({
				window,
				alerts: z.number(),
				byKind: kinds,
				decisions: z.number(),
				bans: z.number(),
				previous: z.object({ alerts: z.number(), bans: z.number() }).nullable(),
				last24Hours: z.object({ alerts: z.number(), byKind: kinds, previous24Hours: z.number().nullable() }),
				activeBans: z
					.object({ bans: z.number(), decisions: z.number(), at: z.string(), truncated: z.boolean() })
					.nullable(),
				lastSync,
			}),
			destructive: false,
		},
		top_threats: {
			description:
				"The most frequent CrowdSec scenarios, source addresses, countries, AS organisations and targeted paths on this site over 7, 30 or 90 days, most alerts first. " +
				"The counts are sums of each day's top 25, so values outside a day's top 25 are undercounted.",
			route: TOOL_ROUTES.top,
			input: z.object({
				days,
				limit: z.number().int().min(1).max(MAX_TOP).optional().describe(`Rows per list, 1 to ${MAX_TOP}. Default 10.`),
			}),
			output: z.object({
				window,
				scenarios: ranking,
				sources: ranking,
				countries: ranking.describe("ISO 3166 country codes."),
				asNames: ranking,
				paths: ranking,
				lastSync,
			}),
			destructive: false,
		},
		active_decisions: {
			description:
				"The site's own decisions CrowdSec enforces now (bans and captchas), read live from the Local API, soonest to expire first. " +
				"The community blocklist and lists are not listed: communityBlocklist gives their count from the plugin's daily count. " +
				"Use the id with remove_ban's address, or to tell an administrator what is blocked.",
			route: TOOL_ROUTES.decisions,
			input: z.object({
				limit: z.number().int().min(1).max(MAX_DECISIONS).optional().describe(`Decisions to return, 1 to ${MAX_DECISIONS}. Default 50.`),
			}),
			output: z.object({
				readAt: z.string(),
				total: z.number().describe("The site's own active decisions. Community blocklist and list decisions are not in this list."),
				truncated: z.boolean(),
				communityBlocklist: z
					.object({
						addresses: z.number().nullable().describe("Addresses the community blocklist and lists block, or null when there were too many to count."),
						at: z.string().describe("When they were last counted, once a day."),
					})
					.nullable(),
				decisions: z.array(
					z.object({
						id: z.number(),
						value: z.string(),
						scenario: z.string(),
						type: z.string(),
						origin: z.string(),
						remainingSeconds: z.number(),
						expiresAt: z.string(),
						country: z.string(),
						asName: z.string(),
					}),
				),
			}),
			destructive: false,
		},
		ip_alerts: {
			description:
				"The alerts CrowdSec holds for one address or range, newest first, read live from the Local API, with each alert's decisions. " +
				"Matches the alert's source exactly. communityBlocklist lists any community blocklist or list decision on the address.",
			route: TOOL_ROUTES.ipAlerts,
			input: z.object({ address }),
			output: z.object({
				address: z.string(),
				truncated: z.boolean(),
				communityBlocklist: z
					.array(z.object({ id: z.number(), origin: z.string(), scenario: z.string(), type: z.string(), remainingSeconds: z.number() }))
					.describe("Active community blocklist (CAPI) or list decisions on exactly this address. Empty when it is on neither."),
				alerts: z.array(
					z.object({
						id: z.number(),
						startedAt: z.string(),
						kind: z.enum(["waf", "bot", "behaviour", "manual"]),
						scenario: z.string(),
						country: z.string(),
						asName: z.string(),
						path: z.string(),
						decisions: z.array(z.object({ id: z.number(), type: z.string(), remainingSeconds: z.number() })),
					}),
				),
			}),
			destructive: false,
		},
		traffic_summary: {
			description:
				"Malicious traffic the firewall bouncer discarded on this site over the last 7, 30 or 90 days: packets and bytes by origin (the CrowdSec community blocklist, the site's own detections, manual bans), " +
				"their share of the packets the bouncer checked, web requests the AppSec engine inspected and blocked, the bot challenge at each stage, and the active decisions by origin now. " +
				"From the site's own CrowdSec metrics, sampled with each sync. enabled is false when no metrics URL is set. window.partial is true when sampling started inside the window.",
			route: TOOL_ROUTES.traffic,
			input: z.object({ days }),
			output: z.object({
				window,
				enabled: z.boolean(),
				sampledSince: z.string().nullable().describe("When metrics sampling started, ISO 8601."),
				discarded: z.object({ packets: z.number(), bytes: z.number(), packetsByOrigin: origins, bytesByOrigin: origins }),
				processedPackets: z.number().describe("Packets the firewall bouncer checked."),
				share: z.number().nullable().describe("Discarded packets as a share of the packets checked, 0 to 1."),
				appsec: z.object({ inspected: z.number(), blocked: z.number() }),
				challenge: z.object({ requested: z.number(), submitted: z.number(), accepted: z.number(), rejected: z.number(), exempt: z.number() }),
				activeByOrigin: origins.nullable().describe("Active decisions by origin now, from the security engine."),
			}),
			destructive: false,
		},
		alerts_explorer: {
			description:
				"Explore the CrowdSec alerts stored for this site, as the CrowdSec alerts page does: one period, optionally one kind, filtered by address or CIDR range, country, scenario, behaviour, AS organisation, target path or the CrowdSec agent (engine) that raised them. " +
				"Answers the matching total, up to two breakdowns (the top five values with their share and the rest as other), and the alerts grouped by source address, latest first, with the local hints the page shows: bannedUntil when a decision is still running, and seenBefore when the address had alerts on days before the period. " +
				"From the plugin's stored alert log (lastSync), never from CrowdSec's cloud, so there is no reputation data. partial is true when the period holds more stored alerts than one call reads: pick a shorter period. Use ip_alerts for one address's live alerts.",
			route: TOOL_ROUTES.explorer,
			input: z.object({
				period: z.enum(EXPLORER_PERIODS).optional().describe("1h, 24h, 3d, 7d or 30d back from now (7d and 30d are local days, today included), or all for everything kept. Default 24h."),
				kind: z.enum(["waf", "bot", "behaviour", "manual"]).optional().describe("Only alerts of this kind."),
				address: address.optional().describe("Only alerts from this address, or from addresses inside this CIDR range."),
				country: z.string().length(2).optional().describe("ISO 3166 country code."),
				scenario: z.string().max(200).optional().describe("A scenario name, such as crowdsecurity/http-probing."),
				behaviour: z.enum(BEHAVIOURS).optional().describe("The behaviour the plugin reads from the scenario name."),
				asName: z.string().max(200).optional().describe("An AS organisation, as the alerts name it."),
				path: z.string().max(200).optional().describe("A targeted path, such as /.env."),
				engine: z.string().max(200).optional().describe("Only alerts raised by this CrowdSec agent: its machine_id, as groups[].engines[].id gives it."),
				breakdowns: z.array(z.enum(DIMENSIONS)).max(2).optional().describe("Up to two dimensions to break the alerts down by. Default ip and behaviour."),
				limit: z.number().int().min(1).max(MAX_GROUPS).optional().describe(`Address groups per page, 1 to ${MAX_GROUPS}. Default 20.`),
				page: z.number().int().min(0).optional().describe("The page of address groups, from 0."),
				until: z.string().optional().describe("For a page after the first: the period.until the first page answered with, so the period does not move between pages."),
			}),
			output: z.object({
				period: z.object({ name: z.enum(EXPLORER_PERIODS), since: z.string(), until: z.string() }),
				total: z.number(),
				partial: z.boolean(),
				breakdowns: z.array(
					z.object({
						dimension: z.enum(DIMENSIONS),
						total: z.number(),
						top: z.array(z.object({ value: z.string(), alerts: z.number(), share: z.number().describe("0 to 1.") })),
						other: z.number(),
					}),
				),
				groups: z.object({
					total: z.number(),
					nextPage: z.number().nullable(),
					items: z.array(
						z.object({
							address: z.string(),
							country: z.string(),
							asName: z.string(),
							alerts: z.number(),
							firstSeen: z.string(),
							lastSeen: z.string(),
							wafAlerts: z.number(),
							scenarios: ranking,
							paths: ranking,
							decisions: z.number(),
							bannedUntil: z.string().nullable(),
							seenBefore: z.boolean(),
							engines: z
								.array(z.object({ id: z.string().describe("The agent's machine_id."), name: z.string().describe("Its name from the Engine names setting, or the id.") }))
								.describe("The CrowdSec agents that raised the address's alerts, most first. Empty for alerts stored before 0.1.1."),
						}),
					),
				}),
				lastSync,
			}),
			destructive: false,
		},
		ban_ip: {
			description:
				"Ban an address or range in CrowdSec, or make it solve a captcha, for a fixed time. Needs Allow changes on in the plugin's settings. " +
				"Refused, with the rule named, for: the address this MCP client connects from, the site's and the Local API's addresses, the Protected addresses setting, private, loopback, link-local, CGNAT and multicast space, ranges wider than /16 (IPv4) or /48 (IPv6), and addresses on a CrowdSec allowlist. " +
				"Confirm the address with the person before calling. The client's own address is its egress, which may not be the person's: when the person's own address could be covered, ask them for it and check. When clientAddressChecked is false, say that the ban could not be checked against the client's address.",
			route: TOOL_ROUTES.ban,
			input: z.object({
				address,
				duration: z.enum(Object.keys(BAN_DURATIONS) as [string, ...string[]]).describe("How long the decision lasts."),
				type: z.enum(["ban", "captcha"]).optional().describe("Default ban."),
				note: z.string().max(MAX_NOTE).optional().describe("Why, recorded with the decision."),
			}),
			output: writeOutput,
			destructive: true,
		},
		remove_ban: {
			description:
				"Remove the site's own active decisions on exactly one address or range. Needs Allow changes on. " +
				"Community blocklist and list decisions are not removed, since CrowdSec adds them back: the answer says when only those block the address. " +
				"Removes a few per call: when remaining is above zero, call again.",
			route: TOOL_ROUTES.removeBan,
			input: z.object({ address }),
			output: writeOutput,
			destructive: true,
		},
		delete_alert: {
			description:
				"Delete one CrowdSec alert by id. Needs Allow changes on. Refused while any of the alert's decisions is active or ended less than two minutes ago, " +
				"because deleting an alert deletes its decisions where firewalls never hear of it. To lift a ban, use remove_ban.",
			route: TOOL_ROUTES.deleteAlert,
			input: z.object({ id: z.number().int().min(1).describe("The alert id.") }),
			output: writeOutput,
			destructive: true,
		},
	};
}
