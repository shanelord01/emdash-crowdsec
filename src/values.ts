/**
 * Coerce a stored number into range, or fall back.
 *
 * Absent means absent: `ctx.kv.get` answers `null` for an unset key, and
 * `Number(null)` is 0, which would silently clamp to `min` instead of
 * using the default. Booleans coerce just as happily, so the accepted
 * input types are named rather than inferred.
 */
export function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
	if (typeof value !== "number" && typeof value !== "string") return fallback;
	if (typeof value === "string" && !value.trim()) return fallback;
	const n = Number(value);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(max, Math.max(min, Math.trunc(n)));
}

export function asRecord(input: unknown): Record<string, unknown> {
	return typeof input === "object" && input !== null && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
}

export function str(value: unknown): string {
	return typeof value === "string" ? value.trim() : "";
}
