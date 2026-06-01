#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/build-target.sh"
GO_BIN="${GO_BIN:-${ROOT_DIR}/.tools/go/bin/go}"
if [[ ! -x "${GO_BIN}" ]]; then
  GO_BIN="$(command -v go)"
fi
HOST_GOOS="$("${GO_BIN}" env GOHOSTOS)"

TARGETS=(
  # aix/ppc64 — unsupported

  darwin/amd64
  darwin/arm64

  # dragonfly/amd64 — unsupported

  # freebsd/386 — unsupported
  # freebsd/amd64 — unsupported
  # freebsd/arm — unsupported
  # freebsd/arm64 — unsupported
  # freebsd/riscv64 — unsupported

  # illumos/amd64 — unsupported

  linux/386
  linux/amd64
  linux/arm
  linux/arm64
  linux/loong64
  linux/mips
  linux/mips64
  linux/mips64le
  linux/mipsle
  linux/ppc64
  linux/ppc64le
  linux/riscv64
  linux/s390x

  # netbsd/386 — unsupported
  # netbsd/amd64 — unsupported
  # netbsd/arm — unsupported
  # netbsd/arm64 — unsupported

  # openbsd/386 — unsupported
  # openbsd/amd64 — unsupported
  # openbsd/arm — unsupported
  # openbsd/arm64 — unsupported
  # openbsd/mips64 — unsupported
  # openbsd/ppc64 — unsupported
  # openbsd/riscv64 — unsupported

  # solaris/amd64 — unsupported
)

if [[ "${HOST_GOOS}" == "darwin" ]]; then
  TARGETS+=(
    ios/amd64
    ios/arm64
  )
else
  echo "Skipping iOS targets; Go requires external linking through the Apple SDK."
fi

FAILED=()
for target in "${TARGETS[@]}"; do
  if ! bash "${SCRIPT}" "${target}"; then
    FAILED+=("${target}")
  fi
done

echo ""
echo "Done. ${#TARGETS[@]} targets attempted."
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "Failed (${#FAILED[@]}):" >&2
  for t in "${FAILED[@]}"; do
    echo "  ${t}" >&2
  done
  exit 1
fi
echo "All targets built successfully."
