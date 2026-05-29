#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_VERSION="${GO_VERSION:-1.25.5}"
TOOLS_DIR="${ROOT_DIR}/.tools"
GO_DIR="${TOOLS_DIR}/go"

case "$(uname -m)" in
  x86_64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  armv7l|armv6l) GO_ARCH="armv6l" ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! need_cmd curl; then
  echo "curl is required. Install curl with your system package manager." >&2
  exit 1
fi

mkdir -p "${TOOLS_DIR}"

if [[ ! -x "${GO_DIR}/bin/go" ]] || ! "${GO_DIR}/bin/go" version | grep -q "go${GO_VERSION} "; then
  echo "Installing Go ${GO_VERSION} for linux/${GO_ARCH} under ${GO_DIR}..."
  rm -rf "${GO_DIR}" "${TOOLS_DIR}/go.tar.gz"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "${TOOLS_DIR}/go.tar.gz"
  tar -C "${TOOLS_DIR}" -xzf "${TOOLS_DIR}/go.tar.gz"
fi

echo "Using $("${GO_DIR}/bin/go" version)"
cd "${ROOT_DIR}"
GOTOOLCHAIN=local "${GO_DIR}/bin/go" mod download

cat <<EOF

Dependencies are ready.

For this shell:
  export PATH="${GO_DIR}/bin:\$PATH"

Build:
  ./scripts/build.sh

Test:
  ./scripts/test.sh
EOF