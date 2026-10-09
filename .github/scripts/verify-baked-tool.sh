#!/usr/bin/env bash
#
# Verifies that a CI tool baked into the ci-runner image is present and is the
# exact version this repository pins, and fails closed otherwise (issue #19).
#
#   verify-baked-tool.sh <tool> <module path> <version>
#   verify-baked-tool.sh gosec github.com/securego/gosec/v2 v2.29.0
#
# It never installs anything. A missing tool or a version mismatch means the
# image is wrong, and a network install over it would hide exactly that — it is
# how an unconditional `go install golangci-lint@v2.12.2` undid the image's
# baked version, which cannot be linted around on Go 1.27.
#
# The version is read from the binary's embedded Go build info
# (`go version -m`), never from the tool's own --version output: a
# `go install`ed gosec prints "dev" whatever version was built, so its own
# output cannot prove which version ran. Build info also names the module, so
# an unrelated binary that happens to share the tool's name is rejected too.
#
# Tested by verify-baked-tool_test.sh with stub tools; CI runs that test in the
# Lint job before any baked tool is trusted.
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

got="$(printf '%s\n' "$info" | awk -v m="$module" '$1 == "mod" && $2 == m { print $3; exit }')"
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
