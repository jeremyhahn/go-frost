### Changed
- **`make release-alpha`** (#17) is the company release-alpha template v2.3.9,
  vendored as `make/release-alpha.mk`. The version is explicit
  (`make release-alpha VERSION=vX.Y.Z-alpha`, no auto-increment), every git
  write signs through `agent-git.sh`, the tag is annotated, only that tag and
  the release commit are pushed (atomically, to `origin`), and it refuses to
  cut without a matching `CHANGELOG.md` section. The v1 recipe it replaces
  bumped PATCH only, made unsigned lightweight tags, pushed every local tag
  and let a failed VERSION commit be tagged anyway. The Makefile's build
  version variable is renamed `VERSION` → `BUILD_VERSION` so it cannot shadow
  the release argument
- **`make changelog-assemble`** (#17) is the committed assembly step of
  release-versioning.md §5: `make changelog-assemble VERSION=vX.Y.Z-alpha`
  folds `[Unreleased]` and every `changelog.d/` fragment into a dated
  `## [X.Y.Z-alpha]` section, merging subsections in Keep a Changelog order,
  removes the fragments and commits through `agent-git.sh`. `make
  release-alpha` refuses while any fragment remains, so no entry is left
  behind a published tag. `make test-release-alpha` runs both targets'
  regression tests against a temporary remote, in CI's Lint job
