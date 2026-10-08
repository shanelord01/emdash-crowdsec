#!/usr/bin/env bash
#
# Run the plugin's suite against a list of EmDash versions and print which
# combinations pass.
#
# Why this exists: `@emdash-cms/plugin-test` pins `emdash` exactly (0.2.6 pins
# 1.0.1), so out of the box a plugin is only ever tested against the one host
# version the harness chose. pnpm `overrides` rewire the harness's own pinned
# dependency, which is how a range becomes testable at all.
#
# That is a workaround, not a supported path. Nothing stops a future plugin-test
# from importing a symbol that exists only in its pinned host, and the failure
# would look like a plugin bug. The baseline row (no overrides) is therefore not
# optional: it is what tells a harness breakage apart from a plugin regression.
#
# The reverse happened with EmDash 1.0: it moved the module the harness loads
# (`emdash/plugin-test-runtime` became `emdash/internal/plugin-test-runtime`),
# so no harness before plugin-test 0.2.6 can start a 1.0 host. A version
# written as `version:harness` also overrides plugin-test, for example
# `1.0.1:0.2.6`.
#
# `--no-baseline` skips the baseline row, for CI jobs that each run one
# version while a separate job runs the suites on their pinned host.
#
# Usage: scripts/compat-matrix.sh [--no-baseline] [version[:harness]...]      (default: 1.0.1)

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

BASELINE=1
if [ "${1:-}" = "--no-baseline" ]; then
	BASELINE=0
	shift
fi

VERSIONS=("${@:-}")
[ -z "${VERSIONS[0]:-}" ] && VERSIONS=(1.0.1)

if [ -n "$(git status --porcelain pnpm-workspace.yaml pnpm-lock.yaml)" ]; then
	echo "refusing to run: pnpm-workspace.yaml or pnpm-lock.yaml already modified" >&2
	exit 1
fi

PKGS=(emdash-crowdsec)

restore() {
	git checkout -- pnpm-workspace.yaml pnpm-lock.yaml 2>/dev/null || true
	pnpm install --no-frozen-lockfile >/dev/null 2>&1 || true
}
trap restore EXIT INT TERM

# Results accumulate as "label|package|value" lines: macOS ships bash 3.2,
# which has no associative arrays, and this has to run here and in CI.
RESULTS=""
FAILED=0

record() { RESULTS="${RESULTS}${1}|${2}|${3}
"; }

lookup() {
	printf '%s' "$RESULTS" | awk -F'|' -v l="$1" -v p="$2" '$1==l && $2==p {print $3; found=1} END {if (!found) print "?"}' | head -1
}

run_suites() {
	label="$1"
	# --no-frozen-lockfile because CI=true makes pnpm imply the opposite, and
	# rewriting the lockfile is the entire point of the override rows.
	if ! install_out=$(pnpm install --no-frozen-lockfile 2>&1); then
		echo "  install failed for $label:"
		printf '%s\n' "$install_out" | tail -15 | sed 's/^/    /'
		for p in "${PKGS[@]}"; do record "$label" "$p" "install-fail"; done
		FAILED=1
		return
	fi
	for p in "${PKGS[@]}"; do
		if out=$(pnpm vitest run 2>&1); then
			# `|| true` matters: with `set -eo pipefail` a grep that matches
			# nothing would kill the script and hide the reason.
			n=$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'Tests +[0-9]+ passed' | grep -oE '[0-9]+' | head -1 || true)
			if [ -z "$n" ]; then
				# The table is cross-checked against the counts published in
				# each README, so a missing number is worth a line rather than
				# a silent "passed". Show what the summary actually looked like.
				echo "  note: no test count parsed for $p ($label); summary was:"
				printf '%s\n' "$out" | tail -6 | sed 's/^/    /'
			fi
			record "$label" "$p" "${n:-passed}"
		else
			echo "  $p failed against $label:"
			# Every failing test with its first error lines, then the summary.
			# A tail of the run shows only the last failure, and a flaky run
			# rarely fails once.
			plain=$(printf '%s\n' "$out" | sed 's/\x1b\[[0-9;]*m//g')
			printf '%s\n' "$plain" | grep -E -A4 '^ *(FAIL|×) |Error:' | head -80 | sed 's/^/    /' || true
			printf '%s\n' "$plain" | tail -6 | sed 's/^/    /'
			record "$label" "$p" "FAIL"
			FAILED=1
		fi
	done
}

if [ "$BASELINE" -eq 1 ]; then
	echo "baseline (harness's own pinned host, no overrides)"
	run_suites "baseline"
fi

for spec in "${VERSIONS[@]}"; do
	v="${spec%%:*}"
	harness=""
	[ "$spec" != "$v" ] && harness="${spec#*:}"
	echo "emdash $v${harness:+ (plugin-test $harness)}"
	git checkout -- pnpm-workspace.yaml pnpm-lock.yaml
	cat >> pnpm-workspace.yaml <<-EOF

	overrides:
	  emdash: $v
	  "@emdash-cms/cloudflare": $v
	  "@emdash-cms/blocks": $v
	EOF
	if [ -n "$harness" ]; then
		printf '  "@emdash-cms/plugin-test": %s\n' "$harness" >> pnpm-workspace.yaml
	fi
	run_suites "$v"
done

echo
printf '%-26s %-12s' "package" "baseline"
for spec in "${VERSIONS[@]}"; do printf '%-12s' "${spec%%:*}"; done
echo
for p in "${PKGS[@]}"; do
	if [ "$BASELINE" -eq 1 ]; then base="$(lookup baseline "$p")"; else base="skipped"; fi
	printf '%-26s %-12s' "$p" "$base"
	for spec in "${VERSIONS[@]}"; do printf '%-12s' "$(lookup "${spec%%:*}" "$p")"; done
	echo
done
echo
echo "numbers are passing tests; FAIL or install-fail means the combination is not supported"

if [ "$FAILED" -ne 0 ]; then
	echo
	echo "at least one combination failed"
	exit 1
fi
