#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v0.1.1}"
BIN_NAME="kubectl-why"
PKG_NAME="why"
ENTRY="./cmd/why"

ROOT_DIR="$(pwd)"
OUT_DIR="${ROOT_DIR}/dist/${VERSION}"
mkdir -p "${OUT_DIR}"

TARGETS=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
)

build_one() {
  local os="$1"
  local arch="$2"

  local ext=""
  local archive_ext="tar.gz"
  if [[ "${os}" == "windows" ]]; then
    ext=".exe"
    archive_ext="zip"
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  # Use a RETURN trap that embeds the tmpdir path as a literal to avoid "unbound variable"
  # when `set -u` is enabled and the function scope ends.
  trap "rm -rf '${tmpdir}'" RETURN

  local outbin="${tmpdir}/${BIN_NAME}${ext}"
  echo "==> build ${os}/${arch} -> ${outbin}"

  GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "${outbin}" "${ENTRY}"

  local base="${BIN_NAME}_${VERSION#v}_${os}_${arch}"
  local archive="${OUT_DIR}/${base}.${archive_ext}"

  if [[ "${archive_ext}" == "tar.gz" ]]; then
    tar -C "${tmpdir}" -czf "${archive}" "${BIN_NAME}${ext}"
  else
    (cd "${tmpdir}" && zip -q "${archive}" "${BIN_NAME}${ext}")
  fi

  # sha256
  local sha
  sha="$(shasum -a 256 "${archive}" | awk '{print $1}')"
  echo "    sha256: ${sha}"

  echo "${base}.${archive_ext}  ${sha}" >> "${OUT_DIR}/SHA256SUMS.txt"
}

main() {
  echo "VERSION=${VERSION}"
  echo "OUT_DIR=${OUT_DIR}"
  echo

  for t in "${TARGETS[@]}"; do
    IFS="/" read -r os arch <<< "${t}"
    build_one "${os}" "${arch}"
  done

  echo
  echo "DONE. Artifacts:"
  ls -1 "${OUT_DIR}"
  echo
  echo "SHA256SUMS:"
  cat "${OUT_DIR}/SHA256SUMS.txt"
}

main "$@"