#!/usr/bin/env bash
set -euo pipefail

workspace="${RED_WIDOW_WORKSPACE:-.}"
policy="${RED_WIDOW_POLICY:-}"
lockfile="${RED_WIDOW_LOCKFILE:-}"
output_dir="${RED_WIDOW_OUTPUT_DIR:-red-widow-results}"
offline="${RED_WIDOW_OFFLINE:-true}"
installed="${RED_WIDOW_INSTALLED:-false}"
fail_on_review="${RED_WIDOW_FAIL_ON_REVIEW:-false}"
strict="${RED_WIDOW_STRICT:-false}"
python_cmd="${PYTHON:-python}"

if ! command -v "$python_cmd" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    python_cmd="python3"
  fi
fi

mkdir -p "$output_dir"

build_gate_args() {
  local format="$1"
  gate_args=(gate --workspace "$workspace" --format "$format")
  if [[ -n "$policy" ]]; then
    gate_args+=(--policy "$policy")
  fi
  if [[ -n "$lockfile" ]]; then
    gate_args+=(--lockfile "$lockfile")
  fi
  if [[ "$offline" == "true" ]]; then
    gate_args+=(--offline)
  fi
  if [[ "$installed" == "true" ]]; then
    gate_args+=(--installed)
  fi
  if [[ "$fail_on_review" == "true" ]]; then
    gate_args+=(--fail-on-review)
  fi
  if [[ "$strict" == "true" ]]; then
    gate_args+=(--strict)
  fi
}

build_inventory_args() {
  local format="$1"
  inventory_args=(inventory --workspace "$workspace" --format "$format")
  if [[ -n "$policy" ]]; then
    inventory_args+=(--policy "$policy")
  fi
  if [[ -n "$lockfile" ]]; then
    inventory_args+=(--lockfile "$lockfile")
  fi
  if [[ "$offline" != "true" ]]; then
    inventory_args+=(--online)
  fi
  if [[ "$installed" != "true" ]]; then
    inventory_args+=(--no-installed)
  fi
}

build_gate_args json
set +e
red-widow "${gate_args[@]}" > "$output_dir/gate.json"
gate_status=$?
set -e

build_gate_args markdown
red-widow "${gate_args[@]}" > "$output_dir/gate.md" || true

build_gate_args sarif
red-widow "${gate_args[@]}" > "$output_dir/gate.sarif" || true

build_inventory_args json
red-widow "${inventory_args[@]}" > "$output_dir/inventory.json" || true

build_inventory_args markdown
red-widow "${inventory_args[@]}" > "$output_dir/inventory.md" || true

decision="$("$python_cmd" - "$output_dir/gate.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("decision", "UNKNOWN"))
PY
)"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "decision=$decision"
    echo "exit-code=$gate_status"
    echo "gate-json=$output_dir/gate.json"
    echo "gate-markdown=$output_dir/gate.md"
    echo "gate-sarif=$output_dir/gate.sarif"
    echo "inventory-json=$output_dir/inventory.json"
  } >> "$GITHUB_OUTPUT"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$output_dir/gate.md" >> "$GITHUB_STEP_SUMMARY"
fi

exit 0
