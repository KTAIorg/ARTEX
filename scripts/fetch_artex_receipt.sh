#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --workflow FILE --run-id ID --source-commit SHA --target TARGET --resolved-receipt FILE --output-file FILE [--run-attempt N]" >&2
  exit 2
}

workflow=""
run_id=""
run_attempt=""
source_commit=""
target=""
resolved_receipt=""
output_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --workflow) workflow="${2:-}"; shift 2 ;;
    --run-id) run_id="${2:-}"; shift 2 ;;
    --run-attempt) run_attempt="${2:-}"; shift 2 ;;
    --source-commit) source_commit="${2:-}"; shift 2 ;;
    --target) target="${2:-}"; shift 2 ;;
    --resolved-receipt) resolved_receipt="${2:-}"; shift 2 ;;
    --output-file) output_file="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ -z "${workflow}" || -z "${run_id}" || -z "${source_commit}" || -z "${target}" || -z "${resolved_receipt}" || -z "${output_file}" ]]; then
  usage
fi
: "${GH_TOKEN:?GH_TOKEN is required}"
repository="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
: "${repository:?GH_REPO or GITHUB_REPOSITORY is required}"

work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/artex-receipt.XXXXXX")
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

gh api "repos/${repository}/actions/workflows/${workflow}" > "${work_dir}/workflow.json"
gh api "repos/${repository}/actions/runs/${run_id}" > "${work_dir}/run.json"
gh api --paginate "repos/${repository}/actions/runs/${run_id}/artifacts?per_page=100" \
  --jq '.artifacts[]' > "${work_dir}/artifacts.jsonl"

binding_args=(
  --workflow-json "${work_dir}/workflow.json"
  --run-json "${work_dir}/run.json"
  --artifacts-jsonl "${work_dir}/artifacts.jsonl"
  --resolved-receipt "${resolved_receipt}"
  --run-id "${run_id}"
  --source-commit "${source_commit}"
  --target "${target}"
  --workflow "${workflow}"
)
if [ -n "${run_attempt}" ]; then
  binding_args+=(--run-attempt "${run_attempt}")
fi
python3 scripts/bind_artex_receipt.py "${binding_args[@]}" \
  --output-file "${work_dir}/selection.json"
artifact_id=$(jq -er '.artifact_id' "${work_dir}/selection.json")
gh api "repos/${repository}/actions/artifacts/${artifact_id}/zip" > "${work_dir}/receipt.zip"
python3 scripts/bind_artex_receipt.py "${binding_args[@]}" \
  --artifact-zip "${work_dir}/receipt.zip" \
  --output-file "${output_file}"
jq -e . "${output_file}" >/dev/null
