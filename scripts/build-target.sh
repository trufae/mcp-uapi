#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <goos/goarch[/goarm]>" >&2
  echo "examples: $0 linux/amd64 | $0 linux/arm64 | $0 linux/arm/v7 | $0 darwin/arm64 | $0 ios/arm64" >&2
  exit 2
fi

TARGET="$1"
IFS=/ read -r GOOS GOARCH GOARM_PART <<<"${TARGET}"
if [[ -z "${GOOS:-}" || -z "${GOARCH:-}" ]]; then
  echo "invalid target ${TARGET}; expected goos/goarch[/goarm]" >&2
  exit 2
fi

GOARM=""
if [[ -n "${GOARM_PART:-}" ]]; then
  GOARM="${GOARM_PART#v}"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-${ROOT_DIR}/.tools/go/bin/go}"
if [[ ! -x "${GO_BIN}" ]]; then
  GO_BIN="$(command -v go)"
fi

OUT_TARGET="${GOOS}-${GOARCH}"
if [[ -n "${GOARM}" ]]; then
  OUT_TARGET="${OUT_TARGET}-v${GOARM}"
fi

cd "${ROOT_DIR}"
mkdir -p bin
echo "Building mcp-uapi for ${TARGET}..."
CGO_VALUE="${CGO_ENABLED:-0}"
if [[ "${GOOS}" == "ios" && -z "${CGO_ENABLED+x}" ]]; then
  CGO_VALUE=1
fi
BUILD_ENV=(
  "CGO_ENABLED=${CGO_VALUE}"
  "GOOS=${GOOS}"
  "GOARCH=${GOARCH}"
  "GOARM=${GOARM}"
  "GOTOOLCHAIN=local"
)
if [[ "${GOOS}" == "ios" && -z "${CC+x}" ]]; then
  GOROOT="$("${GO_BIN}" env GOROOT)"
  IOS_CC="${GOROOT}/misc/ios/clangwrap.sh"
  if [[ -x "${IOS_CC}" ]]; then
    BUILD_ENV+=("CC=${IOS_CC}")
  fi
fi
env "${BUILD_ENV[@]}" "${GO_BIN}" build -trimpath -o "bin/mcp-uapi-${OUT_TARGET}" ./cmd/mcp-uapi
echo "Built ${ROOT_DIR}/bin/mcp-uapi-${OUT_TARGET}"
