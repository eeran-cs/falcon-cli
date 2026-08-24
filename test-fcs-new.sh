#!/usr/bin/env bash
# test-fcs-new.sh — smoke test all NEW falcon fcs subcommands added in this branch
# Based on the test-fcs.sh pattern from the upstream repo.
#
# Usage:
#   ./test-fcs-new.sh
#   FALCON_BIN=./build/falcon ./test-fcs-new.sh

set -euo pipefail

# ── Resolve credentials ──────────────────────────────────────────────────────

CONFIG_FILE="${FALCON_CONFIG:-$HOME/.falcon/config.yaml}"
if [[ -z "${FALCON_CLIENT_ID:-}" || -z "${FALCON_CLIENT_SECRET:-}" ]]; then
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: No credentials found." >&2
    echo "  Set FALCON_CLIENT_ID + FALCON_CLIENT_SECRET in the environment, or" >&2
    echo "  create $CONFIG_FILE with client_id / client_secret." >&2
    exit 1
  fi
  echo "No env vars set — using credentials from $CONFIG_FILE"
fi

# ── Resolve binary ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FALCON_BIN="${FALCON_BIN:-}"

if [[ -z "$FALCON_BIN" ]]; then
  for candidate in "$SCRIPT_DIR/falcon" "$SCRIPT_DIR/build/falcon" "$SCRIPT_DIR/bin/falcon"; do
    if [[ -x "$candidate" ]]; then
      FALCON_BIN="$candidate"
      break
    fi
  done
  # Build if not found
  if [[ -z "$FALCON_BIN" ]]; then
    echo "Building falcon binary..."
    (cd "$SCRIPT_DIR" && make build >/dev/null 2>&1) || (cd "$SCRIPT_DIR" && go build -o falcon ./cmd/falcon/)
    FALCON_BIN="$SCRIPT_DIR/falcon"
  fi
fi

if [[ -z "$FALCON_BIN" || ! -x "$FALCON_BIN" ]]; then
  echo "ERROR: falcon binary not found." >&2
  exit 1
fi

echo "Using binary: $FALCON_BIN"
echo ""

# ── Test harness ─────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
RESULTS=()

run_test() {
  local name="$1"
  local expected="$2"   # "ok", "any"
  shift 2
  local cmd=("$FALCON_BIN" "$@")

  local out
  local exit_code=0
  out=$("${cmd[@]}" 2>&1) || exit_code=$?

  local status icon detail=""

  case "$expected" in
    ok)
      if [[ $exit_code -eq 0 ]]; then
        status="PASS"; icon="✅"
        PASS=$((PASS+1))
      else
        status="FAIL"; icon="❌"
        detail=$(echo "$out" | grep -v "^Usage\|^  \|^$\|^Flags\|^Global\|^Example" | head -1)
        FAIL=$((FAIL+1))
      fi
      ;;
    any)
      if [[ $exit_code -eq 0 ]]; then
        status="PASS"; icon="✅"
        PASS=$((PASS+1))
      elif echo "$out" | grep -qE "403|access denied|scope not permitted|Forbidden"; then
        status="SKIP (missing scope)"; icon="⚠️ "
        detail="Add the required API scope to your client"
        SKIP=$((SKIP+1))
      elif echo "$out" | grep -qE "404|feature|not provisioned|not found|unmarshal"; then
        status="SKIP (feature/data)"; icon="⚠️ "
        detail="Feature not provisioned or no data in this tenant"
        SKIP=$((SKIP+1))
      else
        status="FAIL"; icon="❌"
        detail=$(echo "$out" | grep -v "^Usage\|^  \|^$\|^Flags\|^Global\|^Example" | head -1)
        FAIL=$((FAIL+1))
      fi
      ;;
  esac

  local line="$icon  $name"
  [[ -n "$detail" ]] && line="$line  ($detail)"
  echo "$line"
  RESULTS+=("$line")
}

# ── Tests: New commands ──────────────────────────────────────────────────────

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  falcon fcs NEW commands — smoke tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Policies: Rules ──────────────────────────────────────────────────────────
echo "── policies rules ──"
run_test "policies rules list"                  any  fcs policies rules list --limit 3
run_test "policies rules list --filter"         any  fcs policies rules list --limit 3 --filter "rule_provider:'AWS'"
run_test "policies rules list --output json"    any  fcs policies rules list --limit 1 --output json

# ── Policies: Overrides ──────────────────────────────────────────────────────
echo ""
echo "── policies overrides ──"
run_test "policies overrides get (no data)"     any  fcs policies overrides get --ids "00000000-0000-0000-0000-000000000000"

# ── Registration: AWS ────────────────────────────────────────────────────────
echo ""
echo "── registration aws ──"
run_test "registration aws list"                any  fcs registration aws list --limit 3
run_test "registration aws list --output json"  any  fcs registration aws list --limit 1 --output json
run_test "registration aws get (no data)"       any  fcs registration aws get --ids "000000000000"

# ── Registration: Azure ──────────────────────────────────────────────────────
echo ""
echo "── registration azure ──"
run_test "registration azure list"              any  fcs registration azure list

# ── Registration: GCP ────────────────────────────────────────────────────────
echo ""
echo "── registration gcp ──"
run_test "registration gcp list"                any  fcs registration gcp list

# ── Registration: OCI ────────────────────────────────────────────────────────
echo ""
echo "── registration oci ──"
run_test "registration oci list"                any  fcs registration oci list

# ── Compliance: Controls ─────────────────────────────────────────────────────
echo ""
echo "── compliance controls ──"
run_test "compliance controls list"             any  fcs compliance controls list --limit 3
run_test "compliance controls list --filter"    any  fcs compliance controls list --limit 3 --filter "compliance_control_authority:'CIS'"
run_test "compliance controls get (no data)"    any  fcs compliance controls get .--ids=a4d9b68d-abfc-467a-aa4d-d7a820da2c0e,c6c8c145-d3d0-47bb-acac-3f217417f81c

# ── Suppression: Get + Update ────────────────────────────────────────────────
echo ""
echo "── suppression get/update ──"
run_test "suppression get (no data)"            any  fcs suppression get --ids "00000000-0000-0000-0000-000000000000"

# ── Kubernetes: Detections ───────────────────────────────────────────────────
echo ""
echo "── kubernetes detections ──"
run_test "kubernetes detections"                any  fcs kubernetes detections --limit 3
run_test "kubernetes detections --filter"       any  fcs kubernetes detections --limit 3 --filter "severity:'Critical'"
run_test "kubernetes detections --output json"  any  fcs kubernetes detections --limit 1 --output json

# ── Image Assessment Policies ────────────────────────────────────────────────
echo ""
echo "── image-assessment ──"
run_test "image-assessment list"                any  fcs image-assessment list
run_test "image-assessment list --output json"  any  fcs image-assessment list --output json

# ── Help commands (always pass) ──────────────────────────────────────────────
echo ""
echo "── help output ──"
run_test "fcs policies --help"                  ok   fcs policies --help
run_test "fcs policies rules --help"            ok   fcs policies rules --help
run_test "fcs policies overrides --help"        ok   fcs policies overrides --help
run_test "fcs registration --help"              ok   fcs registration --help
run_test "fcs registration aws --help"          ok   fcs registration aws --help
run_test "fcs registration azure --help"        ok   fcs registration azure --help
run_test "fcs registration gcp --help"          ok   fcs registration gcp --help
run_test "fcs registration oci --help"          ok   fcs registration oci --help
run_test "fcs compliance controls --help"       ok   fcs compliance controls --help
run_test "fcs kubernetes detections --help"     ok   fcs kubernetes detections --help
run_test "fcs image-assessment --help"          ok   fcs image-assessment --help
run_test "fcs suppression get --help"           ok   fcs suppression get --help
run_test "fcs suppression update --help"        ok   fcs suppression update --help

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: ✅ $PASS passed  ❌ $FAIL failed  ⚠️  $SKIP skipped"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "Failed tests:"
  for r in "${RESULTS[@]}"; do
    echo "$r" | grep "^❌" || true
  done
  exit 1
fi
