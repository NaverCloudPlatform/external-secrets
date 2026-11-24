#!/usr/bin/env bash
# External Secrets Operator for NAVER Cloud Platform
# Copyright (c) 2026-present NAVER Cloud Corp.
# Apache-2.0

# Package the chart as a release asset that installs with one command.
#
# A checkout of this repository cannot be installed as it is. templates/crds/
# is produced by `make helm.generate` and is not committed, so `helm install`
# on a fresh clone installs no CRDs, and the bitwarden-sdk-server dependency is
# only fetched when the chart is packaged, so it does not install at all
# before `helm dependency build`.
#
# The release asset carries both and is bound to one published build:
#
#   1. version and appVersion are the fork release (2.14.0 and v2.14.0), not
#      what Chart.yaml holds. A fork release carries the version of the
#      upstream release it is based on, and Chart.yaml is upstream's file,
#      which at an upstream release tag still holds the version of
#      upstream's previous chart (2.13.0 at v2.14.0). Upstream publishes its
#      own chart under the same name and version numbers, so the asset is
#      installed by its release URL, never by version from a chart
#      repository.
#   2. The three image tags are the tag the image was published under: the
#      release tag itself for a release, another published tag for a build
#      packaged from a branch (a release candidate, say). They are pinned
#      rather than left to the appVersion so the asset names the exact image
#      either way. values.yaml in the repository keeps the tags empty; only
#      the packaged copy carries one, and it is rebuilt per release.
#
# The registry stays the values.yaml default. An install in another region sets
# the three repositories to that region's registry.
set -euo pipefail

usage="usage: helm.package-release.sh <chart dir> <bundle dir> <release> <image tag> <output dir>"
HELM_DIR="${1:?$usage}"
BUNDLE_DIR="${2:?$usage}"
RELEASE="${3:-}"
IMAGE_TAG="${4:-}"
OUT_DIR="${5:?$usage}"

# The same release tag form as the image publishing accepts: a chart for
# any other tag would name an image that is never published.
if ! [[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
  echo "error: RELEASE must be a release tag such as v2.14.0 or v2.14.0-rc.1, got '${RELEASE}'" >&2
  exit 1
fi
# The character set of an image tag.
if ! [[ "$IMAGE_TAG" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "error: IMAGE_TAG must be a published image tag (letters, digits, '.', '_', '-'), got '${IMAGE_TAG}'" >&2
  exit 1
fi
# A release image is published under the release tag itself, so a release
# chart that pins anything else names an image that was never published.
if [[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && [ "$IMAGE_TAG" != "$RELEASE" ]; then
  echo "error: release ${RELEASE} must pin IMAGE_TAG=${RELEASE}, got '${IMAGE_TAG}'" >&2
  exit 1
fi
version="${RELEASE#v}"

shopt -s nullglob
generated=("${HELM_DIR}"/templates/crds/*.yaml)
if [ ${#generated[@]} -eq 0 ]; then
  echo "error: ${HELM_DIR}/templates/crds has no CRDs; run make helm.generate first" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chart="${work}/external-secrets"
cp -R "$HELM_DIR" "$chart"
# Environment overlays are applied with -f at deploy time and are never part
# of the archive, which installs as it is.
rm -f "$chart"/values-*.yaml

IMAGE_TAG="$IMAGE_TAG" yq e -i '
  .image.tag = strenv(IMAGE_TAG) |
  .webhook.image.tag = strenv(IMAGE_TAG) |
  .certController.image.tag = strenv(IMAGE_TAG)
' "${chart}/values.yaml"

mkdir -p "$OUT_DIR"
helm package "$chart" --dependency-update \
  --version "$version" --app-version "$RELEASE" \
  --destination "$OUT_DIR" >/dev/null
pkg="${OUT_DIR}/external-secrets-${version}.tgz"
if [ ! -f "$pkg" ]; then
  echo "error: helm package did not produce ${pkg}" >&2
  exit 1
fi

# Check the asset, not the inputs: what a user installs is the archive.
rendered=$(helm template external-secrets "$pkg" --namespace external-secrets)

want_crds=$(yq e -N 'select(.kind == "CustomResourceDefinition") | .metadata.name' "${BUNDLE_DIR}/bundle.yaml" | grep -c .)
got_crds=$(grep -c '^kind: CustomResourceDefinition$' <<<"$rendered" || true)
if [ "$got_crds" -ne "$want_crds" ]; then
  echo "error: ${pkg} renders ${got_crds} CRDs, ${BUNDLE_DIR}/bundle.yaml has ${want_crds}" >&2
  exit 1
fi

want_image="$(yq e '.image.repository' "${HELM_DIR}/values.yaml"):${IMAGE_TAG}"
# `- image:` as well as `image:`: helm's toYaml sorts map keys, so a container
# written with `image` before `name` renders the image on the dash line.
images=$(grep -E '^[[:space:]]*(- )?image:[[:space:]]' <<<"$rendered" |
  sed -E 's/^[[:space:]]*(- )?image:[[:space:]]*//; s/^"//; s/"$//' | sort -u)
if [ "$images" != "$want_image" ]; then
  echo "error: ${pkg} renders images other than ${want_image}:" >&2
  echo "$images" >&2
  exit 1
fi

# The ncloud fields are what this chart adds; a stale bundle would package
# upstream's CRDs without them and still count right.
if [ "$(grep -cE '^[[:space:]]+ncloud:$' <<<"$rendered" || true)" -lt 2 ]; then
  echo "error: ${pkg} renders no ncloud provider in its SecretStore and ClusterSecretStore CRDs" >&2
  exit 1
fi

# The archive is attached to the release by hand, so it must carry neither an
# overlay nor a host from the optional host list; a checkout without the list
# skips that scan.
# Each scan reads the archive into a variable first, so a tar failure stops
# the script (set -e) instead of looking like an empty match, and tells grep's
# "no match" (1) from its own failure (2 and up), which is also a failure here.
listing=$(tar -tzf "$pkg")
rc=0
overlays=$(grep -E '/values-[^/]*\.yaml$' <<<"$listing") || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "error: grep failed (exit ${rc}); the overlay scan did not run" >&2
  exit 1
fi
if [ -n "$overlays" ]; then
  echo "error: ${pkg} contains environment overlays:" >&2
  echo "$overlays" >&2
  exit 1
fi
hosts_file="$(dirname "$0")/internal-hosts.ere"
if [ -f "$hosts_file" ]; then
  internal=$(grep -vE '^(#|$)' "$hosts_file" | paste -sd'|' -)
  # Unpacked rather than streamed: the archive holds the subchart .tgz, a
  # binary member that bash would drop null bytes from, and grep -I skips
  # binary files instead.
  mkdir "${work}/scan"
  tar -xzf "$pkg" -C "${work}/scan"
  rc=0
  leaked=$(grep -rniIE "$internal" "${work}/scan") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "error: grep failed (exit ${rc}); the host scan did not run" >&2
    exit 1
  fi
  if [ -n "$leaked" ]; then
    echo "error: ${pkg} names internal hosts:" >&2
    echo "$leaked" >&2
    exit 1
  fi
fi

if command -v sha256sum >/dev/null; then
  digest=$(sha256sum "$pkg" | cut -d' ' -f1)
else
  digest=$(shasum -a 256 "$pkg" | cut -d' ' -f1)
fi
echo "packaged ${pkg}: chart ${version}, appVersion ${RELEASE}, ${got_crds} CRDs, image ${want_image}"
echo "sha256 ${digest}"
