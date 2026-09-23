#!/usr/bin/env bash
#
# Publishes a release to a Gitea instance: creates (or reuses) the release for
# the tag, then uploads everything in dist/ as assets.
#
# This exists because softprops/action-gh-release talks to the GitHub Releases
# API, which Gitea does not serve -- it answers HTTP 405. That, plus the v4
# artifact actions refusing to run against a GHES-shaped host, is what left
# v0.3.0-alpha with a published Go module and no Release object (#16). Gitea's
# own release API under /api/v1 is GitHub-shaped, so plain curl is enough and
# nothing has to be fetchable from github.com at release time.
#
# Adapted from go-truststrap's, which published its v0.2.0-alpha this way.
#
# The body comes from the tag's CHANGELOG section. The validate job has already
# proved that section exists, so a missing one here is a bug rather than a
# routine case.
#
# Required environment:
#   GITEA_TOKEN         token with write access to the repository
#   TAG                 e.g. v0.2.0-alpha
#   GITHUB_SERVER_URL   the Gitea instance, e.g. http://<gitea-host>:3001
#   GITHUB_REPOSITORY   owner/name
set -euo pipefail

: "${GITEA_TOKEN:?}"; : "${TAG:?}"
: "${GITHUB_SERVER_URL:?}"; : "${GITHUB_REPOSITORY:?}"

# The token goes in a 0600 header file rather than a -H argument, because
# arguments are world-readable through /proc for as long as the curl runs.
AUTH_HEADER="$(mktemp)"
chmod 600 "${AUTH_HEADER}"
trap 'rm -f "${AUTH_HEADER}"' EXIT
printf 'Authorization: token %s\n' "${GITEA_TOKEN}" > "${AUTH_HEADER}"
AUTH="@${AUTH_HEADER}"

BASE="${GITHUB_SERVER_URL}/api/v1/repos/${GITHUB_REPOSITORY}/releases"
VERSION="${TAG#v}"

# A hyphen in the version is the portfolio's prerelease marker (-alpha, -beta,
# -rc), matching how docker/metadata-action gates its :latest tag below.
case "${TAG}" in
  *-*) PRERELEASE=true ;;
  *)   PRERELEASE=false ;;
esac

json_field() {
	python3 -c '
import json, sys
try:
	doc = json.load(sys.stdin)
except Exception:
	sys.exit(0)
if isinstance(doc, dict):
	value = doc.get(sys.argv[1])
	if value is not None:
		print(value)
' "$1"
}

# The CHANGELOG section for exactly this version: from its own heading up to
# the next top-level heading, heading excluded.
notes() {
	awk -v want="## [${VERSION}]" '
		index($0, want) == 1 { collecting = 1; next }
		collecting && /^## / { exit }
		collecting { print }
	' CHANGELOG.md
}

body="$(notes)"
if [ -z "${body//[[:space:]]/}" ]; then
	echo "no CHANGELOG section for ${VERSION}; validate should have caught this" >&2
	exit 1
fi

# Re-running a release must not fail on the second attempt.
release_id="$(curl -sS -H "${AUTH}" "${BASE}/tags/${TAG}" | json_field id)"

if [ -n "${release_id}" ]; then
	echo "release ${TAG} already exists (id ${release_id}); replacing assets"
else
	payload="$(python3 -c '
import json, sys
print(json.dumps({
	"tag_name": sys.argv[1],
	"name": sys.argv[1],
	"body": sys.argv[2],
	"draft": False,
	"prerelease": sys.argv[3] == "true",
}))' "${TAG}" "${body}" "${PRERELEASE}")"

	release_id="$(printf '%s' "${payload}" \
		| curl -sS -X POST -H "${AUTH}" -H 'Content-Type: application/json' \
			--data-binary @- "${BASE}" | json_field id)"

	if [ -z "${release_id}" ]; then
		echo "failed to create the release" >&2
		exit 1
	fi
	echo "created release ${TAG} (id ${release_id}, prerelease=${PRERELEASE})"
fi

# Existing asset names, so a re-run replaces them rather than accumulating
# a second copy of every binary under the same name.
existing="$(curl -sS -H "${AUTH}" "${BASE}/${release_id}/assets" | python3 -c '
import json, sys
try:
	assets = json.load(sys.stdin) or []
except Exception:
	assets = []
for asset in assets:
	print(asset.get("id"), asset.get("name"))
')"

failed=0
for file in dist/*; do
	[ -f "${file}" ] || continue
	name="$(basename "${file}")"

	old="$(printf '%s\n' "${existing}" | awk -v n="${name}" '$2 == n { print $1 }')"
	if [ -n "${old}" ]; then
		curl -sS -X DELETE -H "${AUTH}" "${BASE}/${release_id}/assets/${old}" >/dev/null
	fi

	code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "${AUTH}" \
		-F "attachment=@${file}" "${BASE}/${release_id}/assets?name=${name}")"

	printf '  %-40s http %s\n' "${name}" "${code}"
	case "${code}" in
		2*) ;;
		*) failed=1 ;;
	esac
done

if [ "${failed}" -ne 0 ]; then
	echo "one or more assets failed to upload" >&2
	exit 1
fi

echo "release ${TAG} published with $(find dist -maxdepth 1 -type f | wc -l) assets"
