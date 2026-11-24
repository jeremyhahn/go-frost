#!/usr/bin/env bash
# Usage: verify-baked-tool.sh <tool> <module path> <version>. Fails unless the baked tool's build info (go version -m) names that module and version; never installs.
set -euo pipefail

if [ "$#" -ne 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "usage: $0 <tool> <module path> <version>" >&2
  exit 2
fi
tool="$1" module="$2" want="$3"

if ! bin="$(command -v "$tool")"; then
  echo "$tool is not baked into this runner image; expected $module $want (no network install: fix the image)" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "cannot verify $tool at $bin: no go toolchain on PATH to read its build info" >&2
  exit 1
fi

if ! info="$(go version -m "$bin" 2>&1)"; then
  echo "cannot read Go build info from $tool at $bin; expected $module $want" >&2
  printf '%s\n' "$info" >&2
  exit 1
fi

# awk reads all input so a pipe writer never gets SIGPIPE under pipefail.
got="$(awk -v m="$module" '$1 == "mod" && $2 == m && !seen { print $3; seen = 1 }' <<<"$info")"
if [ -z "$got" ]; then
  echo "$tool at $bin carries no build info for module $module; expected $want" >&2
  printf '%s\n' "$info" >&2
  exit 1
fi

if [ "$got" != "$want" ]; then
  echo "baked $tool at $bin is $module $got; this repo pins $want (raise the pin with the image, never install over it)" >&2
  exit 1
fi

echo "$tool: $module $got ($bin)"
