#!/usr/bin/env bash
set -euo pipefail

TARGET_VERSION="22.04"
BENCHMARK_ID="cis-ubuntu-linux-22.04-usg-profiles"
MODE="audit"
PROFILE="cis_level1_server"
DRY_RUN=0
YES=0
SUPPORTED_PROFILES=(
  "cis_level1_server"
  "cis_level2_server"
  "cis_level1_workstation"
  "cis_level2_workstation"
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
REPORT_DIR="$REPO_ROOT/reports/linux/ubuntu/22.04"

usage() {
  cat <<USAGE
Usage: $0 [--audit|--remediate] [--profile PROFILE] [--dry-run] [--yes]

This wrapper delegates to Canonical Ubuntu Security Guide (usg) CIS profiles.
It does not embed CIS benchmark text and does not replace CIS-CAT Pro or other
authorized compliance evidence.

The default profile is cis_level1_server. Confirm installed profile names with:
  sudo usg list

Supported CIS profile names:
  cis_level1_server
  cis_level2_server
  cis_level1_workstation
  cis_level2_workstation

Remediation mode requires --remediate --yes, including --dry-run previews, and
should only be used after backup, change approval, and lab testing.
USAGE
}

is_supported_profile() {
  local candidate="$1"
  local profile
  for profile in "${SUPPORTED_PROFILES[@]}"; do
    if [[ "$profile" == "$candidate" ]]; then
      return 0
    fi
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit) MODE="audit" ;;
    --remediate) MODE="remediate" ;;
    --profile) PROFILE="${2:?--profile requires a value}"; shift ;;
    --dry-run) DRY_RUN=1 ;;
    --yes) YES=1 ;;
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

write_report_header() {
  local status="$1"
  cat > "$REPORT" <<REPORT
status=$status
benchmark=$BENCHMARK_ID
target_version=$TARGET_VERSION
mode=$MODE
profile=$PROFILE
timestamp_utc=$TIMESTAMP
report=$REPORT
REPORT
}

run_usg() {
  local action="$1"
  set +e
  usg "$action" "$PROFILE" 2>&1 | tee -a "$REPORT"
  local usg_exit_code="${PIPESTATUS[0]}"
  set -e
  {
    echo "usg_exit_code=$usg_exit_code"
    if [[ "$usg_exit_code" -eq 0 ]]; then
      echo "final_status=completed"
    else
      echo "final_status=failed"
    fi
  } | tee -a "$REPORT"
  return "$usg_exit_code"
}

if ! command -v usg >/dev/null 2>&1; then
  write_report_header "manual-tooling-required"
  cat >> "$REPORT" <<REPORT
message=Ubuntu Security Guide (usg) is not installed. Install and enable vendor-supported CIS tooling for Ubuntu Pro or run an authorized scanner such as CIS-CAT Pro.
REPORT
  cat "$REPORT"
  exit 3
fi

if ! is_supported_profile "$PROFILE"; then
  write_report_header "unsupported-profile"
  cat >> "$REPORT" <<REPORT
message=Unsupported CIS profile for this wrapper. Use one of: ${SUPPORTED_PROFILES[*]}
REPORT
  cat "$REPORT"
  exit 2
fi

if [[ "$DRY_RUN" -ne 1 && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "$MODE requires root so usg can collect complete evidence and, for remediation, apply system changes." >&2
  exit 1
fi

PROFILE_LIST="$(usg list 2>&1 || true)"
if ! printf '%s\n' "$PROFILE_LIST" | awk '{print $1}' | grep -Fx -- "$PROFILE" >/dev/null; then
  write_report_header "profile-not-found"
  cat >> "$REPORT" <<REPORT
message=Requested usg profile was not found. Confirm available profiles with: sudo usg list
available_profiles:
$PROFILE_LIST
REPORT
  cat "$REPORT"
  exit 4
fi

case "$MODE" in
  audit)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      write_report_header "dry-run"
      echo "Would run: usg audit $PROFILE" | tee -a "$REPORT"
    else
      write_report_header "running"
      run_usg audit
    fi
    ;;
  remediate)
    if [[ "$YES" -ne 1 ]]; then
      write_report_header "confirmation-required"
      cat >> "$REPORT" <<REPORT
message=Remediation requires explicit --yes after backup, change approval, and lab testing.
would_run=usg fix $PROFILE
REPORT
      cat "$REPORT"
      exit 2
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
      write_report_header "dry-run"
      echo "Would run: usg fix $PROFILE" | tee -a "$REPORT"
    else
      write_report_header "running"
      run_usg fix
    fi
    ;;
esac
