#!/usr/bin/env bash
set -euo pipefail

TARGET_VERSION="24.04"
BENCHMARK_ID="cis-ubuntu-linux-24.04-2.0.0-level1"
REPORT_DIR="reports/linux/ubuntu/24.04"
MODE="audit"
PROFILE="cis_level1_server"
DRY_RUN=0

usage() {
  cat <<USAGE
Usage: $0 [--audit|--remediate] [--profile PROFILE] [--dry-run]

This wrapper prefers Canonical Ubuntu Security Guide (usg) CIS profiles. It does
not embed CIS benchmark text. Confirm the profile name installed on your host
with: usg list
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit) MODE="audit" ;;
    --remediate) MODE="remediate" ;;
    --profile) PROFILE="${2:?--profile requires a value}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  echo "/etc/os-release not found" >&2
  exit 1
fi

if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "$TARGET_VERSION" ]]; then
  echo "Unsupported OS for $BENCHMARK_ID: ${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

mkdir -p "$REPORT_DIR"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$REPORT_DIR/${MODE}-${TIMESTAMP}.txt"

if ! command -v usg >/dev/null 2>&1; then
  cat > "$REPORT" <<REPORT
status=manual-tooling-required
benchmark=$BENCHMARK_ID
message=Ubuntu Security Guide (usg) is not installed. Install and enable the vendor-supported CIS tooling for Ubuntu Pro or run an authorized scanner such as CIS-CAT Pro.
REPORT
  cat "$REPORT"
  exit 3
fi

case "$MODE" in
  audit)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "Would run: usg audit $PROFILE" | tee "$REPORT"
    else
      usg audit "$PROFILE" | tee "$REPORT"
    fi
    ;;
  remediate)
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "Remediation requires root." >&2
      exit 1
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "Would run: usg fix $PROFILE" | tee "$REPORT"
    else
      usg fix "$PROFILE" | tee "$REPORT"
    fi
    ;;
esac
