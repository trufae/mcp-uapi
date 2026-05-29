#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-${ROOT_DIR}/.tools/go/bin/go}"
if [[ ! -x "${GO_BIN}" ]]; then
  GO_BIN="$(command -v go)"
fi

cd "${ROOT_DIR}"
GOTOOLCHAIN=local "${GO_BIN}" test ./...