#!/bin/sh
#
# Folds CHANGELOG fragments into a stamped release section and commits the
# result through agent-git.sh: the "assembly is a committed step performed
# before tagging" of release-versioning.md §5. Run by `make changelog-assemble
# VERSION=vX.Y.Z-alpha`, before `make release-alpha VERSION=vX.Y.Z-alpha`
# (issue #17).
#
# Inputs arrive ONLY as environment parameters set by the Makefile target
# (CL_VERSION, CL_REPO, CL_AGENT_GIT), never as Make text, for the same
# injection reason as the release-alpha template's REL_* names.
#
# What it does, fail-closed and before any write:
#   - the release body is the current `## [Unreleased]` content (which the
#     convention releases normally at the next tag) followed by every file in
#     changelog.d/ except .gitkeep, in file-name order;
#   - `### ` subsections with the same heading are merged, and ordered as Keep
#     a Changelog orders them (Added, Changed, Deprecated, Removed, Fixed,
#     Security; anything else after, in order of first appearance);
#   - the body becomes `## [X.Y.Z-alpha] - YYYY-MM-DD` directly below an
#     emptied `## [Unreleased]`, the fragments are removed, and the change is
#     one commit: `chore(release): assemble CHANGELOG for vX.Y.Z-alpha`.
# Headings inside fenced code blocks are content, never structure, in every
# pass. It refuses on a malformed (or multi-line) version, an unclosed fence
# in [Unreleased] or a fragment, a dirty tree, a version whose heading
# already exists, a CHANGELOG with no `## [Unreleased]` heading, or nothing to
# release.
set -eu

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

ver="${CL_VERSION:-}"
repo="${CL_REPO:-}"
agent_git="${CL_AGENT_GIT:-}"

test -n "$ver" || die 'state the version explicitly: make changelog-assemble VERSION=vX.Y.Z-alpha'
# grep matches line by line, so on its own it would accept "v0.4.0-alpha" +
# newline + anything. Refuse every character a version cannot hold FIRST, so
# the whole value is one line before the grammar is checked.
case "$ver" in
*[!v0-9a-z.-]*) die 'VERSION holds characters a vX.Y.Z-alpha version cannot (a newline, space or similar)' ;;
esac
printf '%s' "$ver" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha$' ||
  die "VERSION is not of the form vX.Y.Z-alpha (no leading zeroes): $ver"
test -n "$repo" || die 'REPO_NAME is empty'
test -x "$agent_git" || die 'AGENT_GIT does not point at an executable agent-git.sh'
test -z "$(git status --porcelain)" || die 'working tree not clean'
test -f CHANGELOG.md || die 'no CHANGELOG.md'

bare="${ver#v}"
heading="## [$bare]"
unreleased='## [Unreleased]'

# Fenced code blocks. Every pass below reads a heading only OUTSIDE a fence, so
# a `## ` or `### ` line quoted in an example is content, never structure. The
# rules are the release-alpha template's (v2.3.9 (b)), which follow CommonMark:
# 0-3 spaces of indent, 3+ backticks or tildes, closed only by the SAME
# character at least as long with nothing after it, a backtick fence's info
# string holding no backtick, and an unclosed fence running to the end of its
# source. code($0) is 1 for a fence delimiter or a line inside a fence.
FENCE_AWK='
  function fence(s,   i, n) {
    i = 1; while (i <= 3 && substr(s, i, 1) == " ") i++
    fch = substr(s, i, 1); if (fch != "~" && fch != "\140") return 0
    n = 0; while (substr(s, i + n, 1) == fch) n++
    info = substr(s, i + n); return n >= 3 ? n : 0
  }
  function code(s,   n) {
    n = fence(s)
    if (open) {
      if (n >= open && fch == opench && info ~ /^[ \t]*$/) open = 0
      return 1
    }
    if (n && !(fch == "\140" && index(info, "\140"))) { open = n; opench = fch; return 1 }
    return 0
  }'

awk -v h="$heading" "$FENCE_AWK"'
  { c = code($0) }
  !c && index($0, h) == 1 { found = 1 }
  END { exit found ? 0 : 1 }' CHANGELOG.md &&
  die "CHANGELOG.md already has a \"$heading\" section"
awk -v u="$unreleased" "$FENCE_AWK"'
  { c = code($0) }
  !c && $0 == u { found = 1 }
  END { exit found ? 0 : 1 }' CHANGELOG.md ||
  die "CHANGELOG.md has no \"$unreleased\" heading to assemble below"

fragments=""
if [ -d changelog.d ]; then
  fragments="$(find changelog.d -mindepth 1 -maxdepth 1 -type f ! -name .gitkeep | LC_ALL=C sort)"
fi
case "$fragments" in
*[[:blank:]]*) die 'a changelog.d/ file name contains whitespace; rename it' ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1. The Unreleased body: lines after the heading, up to the next `## `
#    outside a fence.
awk -v u="$unreleased" "$FENCE_AWK"'
  { c = code($0) }
  !inside && !c && $0 == u { inside = 1; next }
  inside && !c && /^## / { exit }
  inside { print }' CHANGELOG.md >"$tmp/body"

# 2. Fragments, each preceded by a separator line (a control character no
#    Markdown source contains) so text before a fragment's first `### ` is not
#    filed under the previous source's subsection, and a missing trailing
#    newline cannot splice two entries onto one line.
sep="$(printf '\001')"
for f in $fragments; do
  {
    printf '%s\n' "$sep"
    cat "$f"
    printf '\n'
  } >>"$tmp/body"
done

# 3. Group by `### ` heading. Each source chunk is trimmed of leading and
#    trailing blank lines; text before the first `### ` is kept as a preamble.
awk "$FENCE_AWK"'
  function cat_of(h,   w) {
    w = h; sub(/^### +/, "", w); sub(/[^A-Za-z].*$/, "", w)
    return w
  }
  function flush(   i, s, e, out) {
    s = 1; while (s <= nl && lines[s] ~ /^[ \t]*$/) s++
    e = nl; while (e >= s && lines[e] ~ /^[ \t]*$/) e--
    out = ""
    for (i = s; i <= e; i++) out = out lines[i] "\n"
    if (out != "") {
      if (!(key in text)) { order[++nk] = key }
      text[key] = text[key] out
    }
    nl = 0
  }
  BEGIN { key = ""; nk = 0; nl = 0
    split("Added Changed Deprecated Removed Fixed Security", kac, " ")
    for (i = 1; i <= 6; i++) rank[kac[i]] = i }
  $0 == sep { if (open) unclosed = 1; flush(); key = ""; open = 0; next }
  { c = code($0) }
  !c && /^### / { flush(); key = $0; next }
  { lines[++nl] = $0 }
  END {
    if (open) unclosed = 1
    if (unclosed) exit 3
    flush()
    first = 1
    if ("" in text) { printf "%s", text[""]; first = 0 }
    for (r = 1; r <= 7; r++) {
      for (i = 1; i <= nk; i++) {
        k = order[i]
        if (k == "") continue
        c = cat_of(k)
        kr = (c in rank) ? rank[c] : 7
        if (kr != r) continue
        if (!first) printf "\n"
        printf "%s\n%s", k, text[k]
        first = 0
      }
    }
  }' sep="$sep" "$tmp/body" >"$tmp/section" || {
  rc=$?
  test "$rc" -eq 3 || die "grouping the release section failed (awk exit $rc)"
  die 'a fenced code block in [Unreleased] or a changelog.d/ fragment is never closed; folded into CHANGELOG.md it would swallow every section after it. Close it first'
}

test -s "$tmp/section" || die 'nothing to release: [Unreleased] is empty and changelog.d/ has no fragments'

# 4. Rebuild CHANGELOG.md: everything up to `## [Unreleased]`, an empty
#    Unreleased, the new section, then the previous releases untouched.
date="$(date -u +%Y-%m-%d)"
awk -v u="$unreleased" -v h="$heading - $date" -v sect="$tmp/section" "$FENCE_AWK"'
  { c = code($0) }
  !done && !c && $0 == u {
    print; print ""; print h; print ""
    while ((getline l < sect) > 0) print l
    skipping = 1; done = 1; next
  }
  skipping && !c && /^## / { skipping = 0; print "" }
  skipping { next }
  { print }' CHANGELOG.md >"$tmp/CHANGELOG.md"

cat "$tmp/CHANGELOG.md" >CHANGELOG.md

# 5. One commit, through the signing wrapper.
for f in $fragments; do
  "$agent_git" "$repo" rm -q -- "$f"
done
"$agent_git" "$repo" add CHANGELOG.md
"$agent_git" "$repo" commit -m "chore(release): assemble CHANGELOG for $ver"
echo "Assembled CHANGELOG section $heading - $date; now run: make release-alpha VERSION=$ver"
