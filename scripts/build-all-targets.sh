#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/build-target.sh"

TARGETS=(
  # aix/ppc64 — unsupported

  # darwin/amd64 — unsupported
  # darwin/arm64 — unsupported

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
