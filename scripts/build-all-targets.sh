#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/build-target.sh"

TARGETS=(
  aix/ppc64

  darwin/amd64
  darwin/arm64

  dragonfly/amd64

  freebsd/386
  freebsd/amd64
  freebsd/arm
  freebsd/arm64
  freebsd/riscv64

  illumos/amd64

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

  netbsd/386
  netbsd/amd64
  netbsd/arm
  netbsd/arm64

  openbsd/386
  openbsd/amd64
  openbsd/arm
  openbsd/arm64
  openbsd/mips64
  openbsd/ppc64
  openbsd/riscv64

  solaris/amd64
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
