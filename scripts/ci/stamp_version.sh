#!/usr/bin/env bash
# Stamp the package version from a release tag.
#
#   scripts/ci/stamp_version.sh <version>       # e.g. 0.1.0, 0.1.0-beta.2
#
# Rewrites `[package] version` in Cargo.toml.
#
# Why this is needed: release-validate.yml only requires the tag's BASE version
# to match Cargo.toml, so the manifest sits at 0.1.0 between releases and a
# prerelease tag supplies the suffix. Without stamping, a v0.1.0-beta.2 tag
# would package `faultbox-0.1.0.crate` and publish version 0.1.0 — not a
# mislabelled file, the wrong release entirely.
#
# No-ops when Cargo.toml already carries the target version, which keeps
# re-running any release stage idempotent.

set -euo pipefail

VERSION="${1:?usage: stamp_version.sh <version>}"

CURRENT=$(cargo metadata --no-deps --format-version=1 \
    | jq -r '.packages[] | select(.name == "faultbox") | .version')

if [[ "$VERSION" == "$CURRENT" ]]; then
    echo "Version already $VERSION — nothing to stamp."
    exit 0
fi

# First `version = "..."` in the file is [package]. Anchored to the line start
# so a dependency's `version = ` (always indented or inline) cannot match.
perl -i -pe 'if (!$done && /^version = "/) { s/^version = ".*"/version = "'"$VERSION"'"/; $done=1 }' Cargo.toml

STAMPED=$(cargo metadata --no-deps --format-version=1 \
    | jq -r '.packages[] | select(.name == "faultbox") | .version')

if [[ "$STAMPED" != "$VERSION" ]]; then
    echo "::error::Stamp failed: Cargo.toml reports $STAMPED, expected $VERSION"
    exit 1
fi

echo "Stamped package version: $CURRENT -> $VERSION"
