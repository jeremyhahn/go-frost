#!/usr/bin/env bash
#
# Regression tests for `make release-alpha` and `make changelog-assemble`
# (issue #17): the vendored company template make/release-alpha.mk and the
# fragment assembly make/changelog-assemble.sh, as wired into THIS
# repository's Makefile.
#
# Each case copies the real Makefile and make/ into a throwaway git repository
# whose `origin` is a local bare repository, puts a stub agent-git.sh on PATH
# (it records every call, then runs git as a fixed agent identity), and runs
# the real recipe. A refused release must leave the remote's refs untouched
# and must not create a local tag or a release commit; it is the half-released
# state (VERSION committed or tag cut, push failed) the recipe exists to
# prevent. Cases:
#
#   - no VERSION: refused by the explicit-version guard (proves the build
#     version no longer shadows the argument);
#   - malformed VERSION; not on main; unknown remote; unreachable remote;
#   - tag already on the remote, or already local;
#   - dirty working tree;
#   - CHANGELOG heading present only inside a fenced code block;
#   - agent-git.sh failing its commit: no tag is created and nothing pushed;
#   - agent-git.sh not on PATH;
#   - $(shell ...) payloads in every settable input, public and internal: none
#     executes;
#   - fragments pending in changelog.d/: release refused;
#   - make changelog-assemble: refusals (no/bad/multi-line version, unclosed
#     fence, dirty tree, heading
#     already present, nothing to release, no [Unreleased], no wrapper, failed
#     commit) change nothing; $(shell ...) payloads in its inputs never run;
#     headings inside fenced code blocks stay content in every pass;
#     and end to end it merges [Unreleased] and the fragments by subsection
#     into a dated section in one agent-git.sh commit that removes the
#     fragments, after which the release publishes exactly that CHANGELOG;
#   - a successful release with push.followTags=true and an unrelated
#     annotated tag present: exactly the release commit and the named,
#     annotated tag reach the remote, VERSION is written unprefixed, and every
#     git write went through agent-git.sh.
#
# No real signing key, remote or network is touched.
#
#   bash make/release-alpha_test.sh     (or: make test-release-alpha)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
pass() {
  echo "ok: $*"
}

# Isolate git from the host's configuration: no global or system settings
# (a host push.followTags=true or signing config must not decide a result).
export HOME="$work/home"
mkdir -p "$HOME"
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL="$work/home/gitconfig"
: >"$GIT_CONFIG_GLOBAL"
unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
unset VERSION RELEASE_REMOTE REPO_NAME AGENT_GIT MAKEFLAGS MFLAGS

# Stub signing wrapper. Records its argv, fails on demand for one git
# subcommand (STUB_FAIL_ON), and otherwise runs git as a fixed agent identity
# so a commit or tag made outside the wrapper is distinguishable.
stubdir="$work/stubbin"
mkdir -p "$stubdir"
cat >"$stubdir/agent-git.sh" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_LOG"
repo="$1"
shift
if [ -n "${STUB_FAIL_ON:-}" ] && [ "$1" = "$STUB_FAIL_ON" ]; then
  echo "stub agent-git.sh: refusing $1 for $repo" >&2
  exit 1
fi
exec git -c user.name="agent-$repo" -c user.email="agent-$repo@example.invalid" \
  -c commit.gpgsign=false -c tag.gpgsign=false "$@"
EOF
chmod +x "$stubdir/agent-git.sh"

fixture_git() {
  git -c user.name=fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false -c tag.gpgsign=false "$@"
}

CHANGELOG_OK='# Changelog

## [Unreleased]

## [0.4.0-alpha] - 2026-09-23

### Changed
- something
'

# new_case <name> [changelog-text]: builds $case_dir/{remote.git,work} and
# sets the globals the assertions use. The work tree is on main, clean, and
# in sync with the remote.
new_case() {
  case_name="$1"
  case_dir="$work/$case_name"
  local changelog="${2:-$CHANGELOG_OK}"
  mkdir -p "$case_dir"
  remote="$case_dir/remote.git"
  wt="$case_dir/work"
  export STUB_LOG="$case_dir/agent-git.log"
  : >"$STUB_LOG"
  unset STUB_FAIL_ON
  git init -q --bare "$remote"
  git init -q -b main "$wt"
  cp "$repo_root/Makefile" "$wt/Makefile"
  mkdir -p "$wt/make"
  cp "$repo_root/make/release-alpha.mk" "$repo_root/make/changelog-assemble.sh" "$wt/make/"
  mkdir -p "$wt/changelog.d"
  : >"$wt/changelog.d/.gitkeep"
  printf '0.3.0-alpha\n' >"$wt/VERSION"
  printf '%s' "$changelog" >"$wt/CHANGELOG.md"
  fixture_git -C "$wt" add -A
  fixture_git -C "$wt" commit -q -m fixture
  git -C "$wt" remote add origin "$remote"
  git -C "$wt" push -q origin main
  remote_before="$(git --git-dir="$remote" for-each-ref --format='%(objectname) %(refname)')"
  head_before="$(git -C "$wt" rev-parse HEAD)"
}

# release [make args...]: runs the recipe in the case's work tree with the
# stub wrapper on PATH; sets $rc and $out.
release() {
  rc=0
  out="$(cd "$wt" && PATH="$stubdir:$PATH" make --no-print-directory release-alpha "$@" 2>&1)" || rc=$?
}

# assemble [make args...]: as release, for make changelog-assemble.
assemble() {
  rc=0
  out="$(cd "$wt" && PATH="$stubdir:$PATH" make --no-print-directory changelog-assemble "$@" 2>&1)" || rc=$?
}

# expect_refused <needle>: the release failed with a message containing
# <needle>, and nothing was published or committed or tagged.
expect_refused() {
  local needle="$1"
  if [ "$rc" -eq 0 ]; then
    fail "$case_name: release succeeded; expected refusal"
    printf '%s\n' "$out" >&2
    return
  fi
  case "$out" in
  *"$needle"*) ;;
  *)
    fail "$case_name: refusal message lacks: $needle"
    printf '%s\n' "$out" >&2
    ;;
  esac
  expect_nothing_published
  if [ "$(git -C "$wt" rev-parse HEAD)" != "$head_before" ]; then
    fail "$case_name: a commit was made on a refused release"
  fi
  if git -C "$wt" rev-parse -q --verify refs/tags/v0.4.0-alpha >/dev/null; then
    fail "$case_name: tag v0.4.0-alpha was created on a refused release"
  fi
  if [ "$(cat "$wt/VERSION")" != "0.3.0-alpha" ] && [ "$case_name" != commit-fails ]; then
    fail "$case_name: VERSION was rewritten on a refused release"
  fi
  pass "$case_name"
}

expect_nothing_published() {
  local after
  after="$(git --git-dir="$remote" for-each-ref --format='%(objectname) %(refname)')"
  if [ "$after" != "$remote_before" ]; then
    fail "$case_name: remote refs changed on a refused release"
    diff <(printf '%s\n' "$remote_before") <(printf '%s\n' "$after") >&2 || true
  fi
}

# --- refusals ---------------------------------------------------------------

new_case no-version
release
expect_refused "state the version explicitly"

new_case malformed-version
release VERSION=0.4.0-alpha
expect_refused "is not of the form vX.Y.Z-alpha"

# grep matches per line; a value with a newline must not pass as its first line.
new_case multiline-version
release "VERSION=v0.4.0-alpha
junk"
expect_refused "0.4.0-alpha"

new_case leading-zero
release VERSION=v0.04.0-alpha
expect_refused "is not of the form vX.Y.Z-alpha"

new_case not-on-main
git -C "$wt" checkout -q -b feature
release VERSION=v0.4.0-alpha
expect_refused "releases are cut from main"

new_case unknown-remote
release VERSION=v0.4.0-alpha RELEASE_REMOTE=dev
expect_refused "no git remote named dev"

new_case unreachable-remote
git -C "$wt" remote add gone "$case_dir/does-not-exist.git"
release VERSION=v0.4.0-alpha RELEASE_REMOTE=gone
expect_refused "could not reach gone"

new_case tag-on-remote
fixture_git -C "$wt" tag -a v0.4.0-alpha -m elsewhere
git -C "$wt" push -q origin refs/tags/v0.4.0-alpha
git -C "$wt" tag -d v0.4.0-alpha >/dev/null
remote_before="$(git --git-dir="$remote" for-each-ref --format='%(objectname) %(refname)')"
release VERSION=v0.4.0-alpha
expect_refused "already exists on origin"

new_case tag-local
fixture_git -C "$wt" tag -a v0.4.0-alpha -m local
release VERSION=v0.4.0-alpha
if [ "$rc" -eq 0 ]; then fail "tag-local: release succeeded"; fi
case "$out" in *"already exists locally"*) ;; *) fail "tag-local: wrong message: $out" ;; esac
expect_nothing_published
pass tag-local

new_case dirty-tree
printf 'scratch\n' >"$wt/scratch.txt"
release VERSION=v0.4.0-alpha
expect_refused "working tree not clean"

new_case no-changelog-section '# Changelog

## [Unreleased]

- mentions 0.4.0-alpha in prose only
### [0.4.0-alpha]
'
release VERSION=v0.4.0-alpha
expect_refused 'no "## [0.4.0-alpha]" section heading'

new_case fenced-only-changelog '# Changelog

## [Unreleased]

Example of a release heading:

````markdown
```
## [0.4.0-alpha] - 2026-09-23
```
## [0.4.0-alpha] - 2026-09-23
````
'
release VERSION=v0.4.0-alpha
expect_refused 'no "## [0.4.0-alpha]" section heading'

new_case unclosed-fence '# Changelog

~~~
## [0.4.0-alpha] - 2026-09-23
'
release VERSION=v0.4.0-alpha
expect_refused 'no "## [0.4.0-alpha]" section heading'

# Named explicitly rather than by dropping the stub from PATH: a host with a
# real agent-git.sh on PATH must never have it reached from this test.
new_case no-agent-git
release VERSION=v0.4.0-alpha "AGENT_GIT=$case_dir/missing/agent-git.sh"
expect_refused "AGENT_GIT does not point at an executable"

# A failed VERSION commit must stop the release: v1's `|| true` tagged anyway.
new_case commit-fails
export STUB_FAIL_ON=commit
release VERSION=v0.4.0-alpha
unset STUB_FAIL_ON
expect_refused "refusing commit"
if grep -q '^go-frost tag ' "$STUB_LOG" || grep -q '^go-frost push ' "$STUB_LOG"; then
  fail "commit-fails: tag or push attempted after the commit failed"
fi

# --- injection --------------------------------------------------------------

# A $(shell ...) payload in any settable input must arrive as literal text,
# never execute. Every case must be refused by a guard except REPO_NAME, which
# no guard checks for shape; that one must still not execute, so it is run
# against a remote whose tag already exists to stop it before any write.
# The CL_* names belong to changelog-assemble, but a command-line variable is
# exported into EVERY recipe's environment unless unexported, so they are
# live on the release path too.
for var in VERSION RELEASE_REMOTE REPO_NAME AGENT_GIT \
  REL_VERSION REL_REMOTE REL_REPO REL_AGENT_GIT \
  CL_VERSION CL_REPO CL_AGENT_GIT; do
  new_case "inject-$var"
  canary="$case_dir/CANARY"
  fixture_git -C "$wt" tag -a v0.4.0-alpha -m blocker
  git -C "$wt" push -q origin refs/tags/v0.4.0-alpha
  git -C "$wt" tag -d v0.4.0-alpha >/dev/null
  remote_before="$(git --git-dir="$remote" for-each-ref --format='%(objectname) %(refname)')"
  if [ "$var" = VERSION ]; then
    release "VERSION=v0.4.0-alpha\$(shell touch $canary)"
  else
    release VERSION=v0.4.0-alpha "$var=\$(shell touch $canary)x"
  fi
  if [ -e "$canary" ]; then
    fail "inject-$var: \$(shell ...) payload executed"
  fi
  if [ "$rc" -eq 0 ]; then
    fail "inject-$var: release succeeded"
  fi
  expect_nothing_published
  pass "inject-$var"
done

# --- changelog fragments ----------------------------------------------------

# A release with fragments still in changelog.d/ would publish a tag whose
# CHANGELOG lacks those entries; it must be refused before anything runs.
new_case fragments-pending
printf '### Fixed\n- pending entry\n' >"$wt/changelog.d/30-pending.md"
fixture_git -C "$wt" add -A
fixture_git -C "$wt" commit -q -m "add fragment"
head_before="$(git -C "$wt" rev-parse HEAD)"
release VERSION=v0.4.0-alpha
expect_refused "changelog.d/ still holds fragments"
[ -z "$(cat "$STUB_LOG")" ] || fail "fragments-pending: agent-git.sh was called"

CHANGELOG_UNRELEASED='# Changelog

Preamble text.

## [Unreleased]

### Removed
- unreleased removal

### Changed
- unreleased change

## [0.3.0-alpha] - 2026-08-22

### Added
- older entry
'

# expect_assemble_refused <needle>: changelog-assemble failed with <needle>,
# made no commit, and left CHANGELOG.md and changelog.d/ as they were.
expect_assemble_refused() {
  local needle="$1"
  if [ "$rc" -eq 0 ]; then
    fail "$case_name: changelog-assemble succeeded; expected refusal"
    printf '%s\n' "$out" >&2
    return
  fi
  case "$out" in
  *"$needle"*) ;;
  *)
    fail "$case_name: refusal message lacks: $needle"
    printf '%s\n' "$out" >&2
    ;;
  esac
  [ "$(git -C "$wt" rev-parse HEAD)" = "$head_before" ] ||
    fail "$case_name: a commit was made on a refused assembly"
  git -C "$wt" diff --quiet HEAD -- CHANGELOG.md changelog.d ||
    fail "$case_name: CHANGELOG.md or changelog.d/ changed on a refused assembly"
  expect_nothing_published
  pass "$case_name"
}

# with_fragment <name> <text>: commits a fragment in the case's work tree.
with_fragment() {
  printf '%s' "$2" >"$wt/changelog.d/$1"
  fixture_git -C "$wt" add -A
  fixture_git -C "$wt" commit -q -m "fragment $1"
  head_before="$(git -C "$wt" rev-parse HEAD)"
}

new_case assemble-no-version "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
assemble
expect_assemble_refused "state the version explicitly"

new_case assemble-bad-version "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
assemble VERSION=0.4.0
expect_assemble_refused "is not of the form vX.Y.Z-alpha"

new_case assemble-multiline-version "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
assemble "VERSION=v0.4.0-alpha
junk"
expect_assemble_refused "VERSION holds characters"

new_case assemble-dirty "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
printf 'scratch\n' >"$wt/scratch.txt"
assemble VERSION=v0.4.0-alpha
expect_assemble_refused "working tree not clean"

new_case assemble-heading-exists
with_fragment 17-a.md $'### Added\n- a\n'
assemble VERSION=v0.4.0-alpha
expect_assemble_refused 'already has a "## [0.4.0-alpha]" section'

new_case assemble-nothing '# Changelog

## [Unreleased]

## [0.3.0-alpha] - 2026-08-22
'
assemble VERSION=v0.4.0-alpha
expect_assemble_refused "nothing to release"

new_case assemble-no-unreleased '# Changelog

## [0.3.0-alpha] - 2026-08-22
'
with_fragment 17-a.md $'### Added\n- a\n'
assemble VERSION=v0.4.0-alpha
expect_assemble_refused 'no "## [Unreleased]" heading'

new_case assemble-no-agent-git "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
assemble VERSION=v0.4.0-alpha "AGENT_GIT=$case_dir/missing/agent-git.sh"
expect_assemble_refused "AGENT_GIT does not point at an executable"

new_case assemble-commit-fails "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- a\n'
export STUB_FAIL_ON=commit
assemble VERSION=v0.4.0-alpha
unset STUB_FAIL_ON
if [ "$rc" -eq 0 ]; then fail "assemble-commit-fails: succeeded"; fi
[ "$(git -C "$wt" rev-parse HEAD)" = "$head_before" ] ||
  fail "assemble-commit-fails: a commit was made"
expect_nothing_published
pass assemble-commit-fails

for var in VERSION REPO_NAME AGENT_GIT CL_VERSION CL_REPO CL_AGENT_GIT; do
  new_case "assemble-inject-$var" "$CHANGELOG_UNRELEASED"
  with_fragment 17-a.md $'### Added\n- a\n'
  canary="$case_dir/CANARY"
  if [ "$var" = VERSION ]; then
    assemble "VERSION=v0.4.0-alpha\$(shell touch $canary)"
  else
    assemble VERSION=v0.4.0-alpha "$var=\$(shell touch $canary)x"
  fi
  [ ! -e "$canary" ] || fail "assemble-inject-$var: \$(shell ...) payload executed"
  expect_nothing_published
  pass "assemble-inject-$var"
done

# Headings quoted in fenced code blocks are content: a fenced `### ` must not
# become a subsection, a fenced `## ` must not end [Unreleased] or the
# section being replaced, and a fenced copy of the version heading or of
# `## [Unreleased]` must not be mistaken for the real one. Includes a ````
# fence holding a ``` line (a naive toggle would "close" it there), and a
# tilde fence alongside backtick ones.
FENCED_CHANGELOG='# Changelog

Example headings, quoted:

```
## [Unreleased]
## [0.4.0-alpha] - 2000-01-01
```

## [Unreleased]

### Changed
- config example:
  ```md
  ## [9.9.9] - not a release
  ### Added
  - not a subsection
  ```
  after the example
- raw example:

```
## [7.7.7] - quoted at column 1
```

## [0.3.0-alpha] - 2026-08-22

### Added
- older entry
'
new_case assemble-fenced "$FENCED_CHANGELOG"
printf '%s' '### Fixed
- nested fence example:
````
```
### Removed
```
## [8.8.8]
````
' >"$wt/changelog.d/10-a.md"
printf '%s' '### Added
- tilde example:
~~~
### Security
~~~
' >"$wt/changelog.d/20-b.md"
printf '%s' '### Deprecated
- plain entry
' >"$wt/changelog.d/30-c.md"
fixture_git -C "$wt" add -A
fixture_git -C "$wt" commit -q -m fragments
head_before="$(git -C "$wt" rev-parse HEAD)"
assemble VERSION=v0.4.0-alpha
if [ "$rc" -ne 0 ]; then
  fail "assemble-fenced: changelog-assemble failed"
  printf '%s\n' "$out" >&2
else
  today="$(date -u +%Y-%m-%d)"
  want="# Changelog

Example headings, quoted:

\`\`\`
## [Unreleased]
## [0.4.0-alpha] - 2000-01-01
\`\`\`

## [Unreleased]

## [0.4.0-alpha] - $today

### Added
- tilde example:
~~~
### Security
~~~

### Changed
- config example:
  \`\`\`md
  ## [9.9.9] - not a release
  ### Added
  - not a subsection
  \`\`\`
  after the example
- raw example:

\`\`\`
## [7.7.7] - quoted at column 1
\`\`\`

### Deprecated
- plain entry

### Fixed
- nested fence example:
\`\`\`\`
\`\`\`
### Removed
\`\`\`
## [8.8.8]
\`\`\`\`

## [0.3.0-alpha] - 2026-08-22

### Added
- older entry"
  got="$(git -C "$wt" show HEAD:CHANGELOG.md)"
  [ "$got" = "$want" ] || {
    fail "assemble-fenced: fenced examples were not preserved"
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") >&2 || true
  }
  pass assemble-fenced
fi

new_case assemble-only-fenced-unreleased '# Changelog

```
## [Unreleased]
```

## [0.3.0-alpha] - 2026-08-22
'
with_fragment 17-a.md $'### Added\n- a\n'
assemble VERSION=v0.4.0-alpha
expect_assemble_refused 'no "## [Unreleased]" heading'

# An unclosed fence would swallow every later section once folded in.
new_case assemble-unclosed-fence "$CHANGELOG_UNRELEASED"
with_fragment 17-a.md $'### Added\n- example:\n```\n### Fixed\n'
assemble VERSION=v0.4.0-alpha
expect_assemble_refused "is never closed"

# End to end: [Unreleased] content and two fragments (one without a trailing
# newline, one carrying two subsections) are merged by subsection in Keep a
# Changelog order, committed as one change that removes the fragments but
# keeps .gitkeep, and the release that follows publishes that CHANGELOG.
new_case assemble-then-release "$CHANGELOG_UNRELEASED"
printf '### Changed\n- fragment change\n  continued' >"$wt/changelog.d/20-b.md"
printf '### Fixed\n- fragment fix\n\n### Added\n- fragment addition\n' >"$wt/changelog.d/10-a.md"
fixture_git -C "$wt" add -A
fixture_git -C "$wt" commit -q -m fragments
head_before="$(git -C "$wt" rev-parse HEAD)"
assemble VERSION=v0.4.0-alpha
if [ "$rc" -ne 0 ]; then
  fail "assemble-then-release: changelog-assemble failed"
  printf '%s\n' "$out" >&2
else
  today="$(date -u +%Y-%m-%d)"
  want="# Changelog

Preamble text.

## [Unreleased]

## [0.4.0-alpha] - $today

### Added
- fragment addition

### Changed
- unreleased change
- fragment change
  continued

### Removed
- unreleased removal

### Fixed
- fragment fix

## [0.3.0-alpha] - 2026-08-22

### Added
- older entry"
  got="$(git -C "$wt" show HEAD:CHANGELOG.md)"
  [ "$got" = "$want" ] || {
    fail "assemble-then-release: assembled CHANGELOG.md differs"
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") >&2 || true
  }
  [ "$(git -C "$wt" ls-tree --name-only HEAD changelog.d/)" = "changelog.d/.gitkeep" ] ||
    fail "assemble-then-release: fragments not removed, or .gitkeep removed"
  [ "$(git -C "$wt" rev-parse HEAD~1)" = "$head_before" ] ||
    fail "assemble-then-release: assembly was not exactly one commit"
  [ "$(git -C "$wt" log -1 --format='%an|%s')" = "agent-go-frost|chore(release): assemble CHANGELOG for v0.4.0-alpha" ] ||
    fail "assemble-then-release: assembly commit not made through agent-git.sh"
  [ -z "$(git -C "$wt" status --porcelain)" ] ||
    fail "assemble-then-release: assembly left the tree dirty"
  expect_nothing_published
  release VERSION=v0.4.0-alpha
  if [ "$rc" -ne 0 ]; then
    fail "assemble-then-release: release after assembly failed"
    printf '%s\n' "$out" >&2
  else
    [ "$(git --git-dir="$remote" show refs/tags/v0.4.0-alpha:CHANGELOG.md)" = "$want" ] ||
      fail "assemble-then-release: published tag does not carry the assembled CHANGELOG"
    [ "$(git --git-dir="$remote" ls-tree --name-only refs/tags/v0.4.0-alpha changelog.d/)" = "changelog.d/.gitkeep" ] ||
      fail "assemble-then-release: published tag still carries fragments"
    pass assemble-then-release
  fi
fi

# --- success ----------------------------------------------------------------

new_case release
git -C "$wt" config push.followTags true
fixture_git -C "$wt" tag -a v0.0.9-stray -m "unrelated annotated tag"
release VERSION=v0.4.0-alpha
if [ "$rc" -ne 0 ]; then
  fail "release: recipe failed"
  printf '%s\n' "$out" >&2
else
  remote_tags="$(git --git-dir="$remote" tag -l)"
  [ "$remote_tags" = "v0.4.0-alpha" ] ||
    fail "release: remote tags are [$remote_tags], want exactly v0.4.0-alpha"
  [ "$(git --git-dir="$remote" cat-file -t refs/tags/v0.4.0-alpha)" = tag ] ||
    fail "release: tag is not annotated"
  [ "$(git --git-dir="$remote" for-each-ref --format='%(taggername)' refs/tags/v0.4.0-alpha)" = agent-go-frost ] ||
    fail "release: tag not made through agent-git.sh as agent-go-frost"
  [ "$(git --git-dir="$remote" rev-parse main)" = "$(git -C "$wt" rev-parse HEAD)" ] ||
    fail "release: remote main is not the release commit"
  [ "$(git --git-dir="$remote" rev-parse 'refs/tags/v0.4.0-alpha^{commit}')" = "$(git -C "$wt" rev-parse HEAD)" ] ||
    fail "release: tag does not point at the release commit"
  [ "$(git --git-dir="$remote" log -1 --format='%an|%s' main)" = "agent-go-frost|chore(release): v0.4.0-alpha" ] ||
    fail "release: release commit author/subject wrong"
  [ "$(git --git-dir="$remote" show main:VERSION)" = "0.4.0-alpha" ] ||
    fail "release: VERSION is not the unprefixed version"
  [ "$(git --git-dir="$remote" rev-parse main~1)" = "$head_before" ] ||
    fail "release: more than one commit was published"
  expected_log='go-frost add VERSION
go-frost commit -m chore(release): v0.4.0-alpha
go-frost tag -a v0.4.0-alpha -m v0.4.0-alpha
go-frost push --atomic --no-follow-tags origin HEAD refs/tags/v0.4.0-alpha'
  [ "$(cat "$STUB_LOG")" = "$expected_log" ] || {
    fail "release: git writes did not match the expected agent-git.sh calls"
    cat "$STUB_LOG" >&2
  }
  pass release
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures failure(s)" >&2
  exit 1
fi
echo "release-alpha: all cases passed"
