#!/usr/bin/env bash
#
# Regression test for verify-baked-tool.sh and its wiring into ci.yml
# (issue #19). Runs the real guard script against stub tools on a PATH that
# contains nothing else of consequence, and asserts:
#
#   - a matching version proceeds;
#   - an absent tool, a mismatched version, a foreign module, missing build
#     metadata, unreadable build info and a missing go toolchain all fail;
#   - in no case is the tool itself executed (the guard runs before analysis)
#     and in no case is a network install attempted (`go install`/`go get`,
#     curl, wget are stubbed to record any call);
#   - ci.yml guards golangci-lint, gosec and govulncheck with this script, in a
#     step before the one that runs the tool, and installs them only on
#     GitHub, at their pins, in a step before the guard.
#
#   bash .github/scripts/verify-baked-tool_test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/verify-baked-tool.sh"
workflow="$here/../workflows/ci.yml"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# A PATH holding only what the guard legitimately needs besides the stubs, so
# a real golangci-lint/gosec/govulncheck/go on the host cannot leak in.
sysbin="$work/sysbin"
mkdir -p "$sysbin"
for util in awk bash cat; do
  ln -s "$(command -v "$util")" "$sysbin/$util"
done

# new_case <name>: fresh stub dir and call log; prints the stub dir.
new_case() {
  local dir="$work/$1"
  mkdir -p "$dir/bin"
  : >"$dir/calls"
  # Record-and-fail stubs for every network install route.
  for net in curl wget; do
    cat >"$dir/bin/$net" <<EOF
#!/usr/bin/env bash
echo "$net \$*" >>"$dir/calls"
exit 1
EOF
    chmod +x "$dir/bin/$net"
  done
  echo "$dir"
}

# stub_tool <dir> <name>: a tool that records any execution.
stub_tool() {
  cat >"$1/bin/$2" <<EOF
#!/usr/bin/env bash
echo "$2 \$*" >>"$1/calls"
exit 0
EOF
  chmod +x "$1/bin/$2"
}

# stub_go <dir> <mode> [build info]: `go version -m` answers per <mode>:
#   info    print the given build info and exit 0
#   error   print a go-style error and exit 1 (not a Go binary)
# Any other go subcommand (install, get, ...) is recorded and fails.
stub_go() {
  local dir="$1" mode="$2" info="${3:-}"
  printf '%s' "$info" >"$dir/buildinfo"
  cat >"$dir/bin/go" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = version ] && [ "\${2:-}" = -m ]; then
  if [ "$mode" = error ]; then
    echo "\$3: could not read Go build info from \$3: not a Go executable" >&2
    exit 1
  fi
  cat "$dir/buildinfo"
  exit 0
fi
echo "go \$*" >>"$dir/calls"
exit 1
EOF
  chmod +x "$dir/bin/go"
}

buildinfo() { # <tool> <module> <version>
  printf '%s: go1.27.0\n\tpath\t%s/cmd/%s\n\tmod\t%s\t%s\th1:AAAA=\n\tdep\tgolang.org/x/tools\tv0.40.0\th1:BBBB=\n' \
    "$1" "$2" "$1" "$2" "$3"
}

# run_guard <dir> <expect: pass|fail> <args...>
run_guard() {
  local dir="$1" expect="$2" rc=0
  shift 2
  env -i PATH="$dir/bin:$sysbin" "$BASH" "$guard" "$@" >"$dir/out" 2>&1 || rc=$?
  case "$expect" in
    pass) [ "$rc" -eq 0 ] || fail "$(basename "$dir"): expected success, got exit $rc: $(cat "$dir/out")" ;;
    fail) [ "$rc" -ne 0 ] || fail "$(basename "$dir"): expected failure, got exit 0: $(cat "$dir/out")" ;;
  esac
  # Before analysis, without a network fallback: nothing may have been called.
  if [ -s "$dir/calls" ]; then
    fail "$(basename "$dir"): guard executed the tool or attempted an install: $(cat "$dir/calls")"
  fi
}

mod=github.com/securego/gosec/v2

# Matching version proceeds.
d="$(new_case match)"; stub_tool "$d" gosec; stub_go "$d" info "$(buildinfo gosec "$mod" v2.29.0)"
run_guard "$d" pass gosec "$mod" v2.29.0

# Absent tool fails.
d="$(new_case absent)"; stub_go "$d" info "$(buildinfo gosec "$mod" v2.29.0)"
run_guard "$d" fail gosec "$mod" v2.29.0
grep -q "not baked" "$d/out" || fail "absent: message does not say the tool is not baked: $(cat "$d/out")"

# Mismatched version fails, older or newer.
for v in v2.28.0 v2.30.0; do
  d="$(new_case "mismatch-$v")"; stub_tool "$d" gosec; stub_go "$d" info "$(buildinfo gosec "$mod" "$v")"
  run_guard "$d" fail gosec "$mod" v2.29.0
done

# A same-named binary from another module fails.
d="$(new_case foreign-module)"; stub_tool "$d" gosec
stub_go "$d" info "$(buildinfo gosec github.com/example/gosec v2.29.0)"
run_guard "$d" fail gosec "$mod" v2.29.0

# Build info with no module line (missing build metadata) fails.
d="$(new_case no-mod-line)"; stub_tool "$d" gosec
stub_go "$d" info "$(printf 'gosec: go1.27.0\n\tpath\tcommand-line-arguments\n')"
run_guard "$d" fail gosec "$mod" v2.29.0

# Build info far over the 64 KiB pipe buffer with the module line early must
# still pass under pipefail (an early-exiting reader on a pipe died of SIGPIPE).
big="$(buildinfo gosec "$mod" v2.29.0)"
for ((i = 0; i < 40000; i++)); do
  big+=$'\n'"$(printf '\tdep\texample.com/padding/module%05d\tv1.0.0\th1:CCCCCCCCCCCCCCCCCCCCCCCCCCCC=' "$i")"
done
d="$(new_case large-buildinfo)"; stub_tool "$d" gosec; stub_go "$d" info "$big"
run_guard "$d" pass gosec "$mod" v2.29.0

# Empty build info fails.
d="$(new_case empty-buildinfo)"; stub_tool "$d" gosec; stub_go "$d" info ""
run_guard "$d" fail gosec "$mod" v2.29.0

# Unreadable build info (not a Go binary) fails.
d="$(new_case unreadable-buildinfo)"; stub_tool "$d" gosec; stub_go "$d" error
run_guard "$d" fail gosec "$mod" v2.29.0

# No go toolchain to read build info with fails.
d="$(new_case no-go)"; stub_tool "$d" gosec
run_guard "$d" fail gosec "$mod" v2.29.0

# Bad invocations fail rather than passing vacuously.
d="$(new_case usage-missing-version)"; stub_tool "$d" gosec; stub_go "$d" info "$(buildinfo gosec "$mod" v2.29.0)"
run_guard "$d" fail gosec "$mod"
d="$(new_case usage-empty-version)"; stub_tool "$d" gosec; stub_go "$d" info "$(buildinfo gosec "$mod" v2.29.0)"
run_guard "$d" fail gosec "$mod" ""

# --- ci.yml wiring -----------------------------------------------------------

# Each baked tool: guarded by this script with its module, and the guard step
# comes before the first line that runs the tool (a `run:` value or a line of
# a `run: |` block).
check_wiring() { # <tool> <module> <run pattern>
  local tool="$1" module="$2" run="$3" guard_line run_line
  guard_line="$(grep -nE "verify-baked-tool\.sh $tool $module \"\\\$[A-Z_]+_VERSION\"" "$workflow" | head -1 | cut -d: -f1 || true)"
  run_line="$(grep -nE "^[[:space:]]*(run: )?$run" "$workflow" | head -1 | cut -d: -f1 || true)"
  if [ -z "$guard_line" ]; then
    fail "ci.yml: $tool is not guarded by verify-baked-tool.sh $tool $module"
    return
  fi
  if [ -z "$run_line" ]; then
    fail "ci.yml: no step runs $tool (pattern: $run)"
    return
  fi
  [ "$guard_line" -lt "$run_line" ] || fail "ci.yml: $tool runs (line $run_line) before its guard (line $guard_line)"
}
check_wiring golangci-lint github.com/golangci/golangci-lint/v2 'golangci-lint run'
check_wiring gosec github.com/securego/gosec/v2 'gosec '
check_wiring govulncheck golang.org/x/vuln 'govulncheck '

# Installed over the network only on GitHub (whose ubuntu-latest bakes none
# of them), never on Gitea where the image bakes them: every install line
# sits in a step gated on github.com, names a pinned version (never
# @latest), uses `go install` (no curl/wget/go get), and comes before the
# guard step that verifies it.
check_install() {
  local line="$1" text="$2" step_line gate tool guard_line
  step_line="$(head -n "$line" "$workflow" | grep -nE '^[[:space:]]*- name:' | tail -1 | cut -d: -f1 || true)"
  gate="$(sed -n "${step_line:-1},${line}p" "$workflow" | grep -cE "^[[:space:]]*if: github\.server_url == 'https://github\.com'[[:space:]]*$" || true)"
  [ "$gate" -ge 1 ] || fail "ci.yml:$line: network install not gated on github.com: $text"
  case "$text" in
    *'go install '*) ;;
    *) fail "ci.yml:$line: tool installed by a route other than a pinned go install: $text" ;;
  esac
  case "$text" in
    *@latest*) fail "ci.yml:$line: tool installed at @latest, not its pin: $text" ;;
    *'@"$'*) ;;
    *) fail "ci.yml:$line: tool install does not name its pinned version variable: $text" ;;
  esac
  for tool in golangci-lint gosec govulncheck; do
    case "$text" in *"/$tool@"*) ;; *) continue ;; esac
    guard_line="$(grep -nE "verify-baked-tool\.sh $tool " "$workflow" | head -1 | cut -d: -f1 || true)"
    [ -n "$guard_line" ] && [ "$line" -lt "$guard_line" ] || fail "ci.yml:$line: $tool is installed after its guard (line ${guard_line:-none})"
  done
}
while IFS=: read -r line text; do
  [[ -z "$line" || "$text" =~ ^[[:space:]]*# ]] && continue
  check_install "$line" "$text"
done < <(grep -nE '(go (install|get)|curl|wget).*(golangci-lint|gosec|govulncheck|x/vuln)' "$workflow" || true)

if [ "$failures" -ne 0 ]; then
  echo "verify-baked-tool: $failures failure(s)" >&2
  exit 1
fi
echo "verify-baked-tool: all cases passed"
