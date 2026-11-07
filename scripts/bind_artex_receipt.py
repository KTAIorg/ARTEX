#!/usr/bin/env python3
"""Bind a resolved ARTEX image to one successful workflow's immutable receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any
from zipfile import BadZipFile, ZipFile


SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MAX_RECEIPT_BYTES = 64 * 1024


class ReceiptBindingError(RuntimeError):
    pass


def load_json_object(path: str, description: str) -> dict[str, Any]:
    try:
        document: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptBindingError(f"could not read {description}") from exc
    if not isinstance(document, dict):
        raise ReceiptBindingError(f"{description} must be a JSON object")
    return document


def require_string(document: dict[str, Any], field: str, description: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ReceiptBindingError(f"{description} has no valid {field}")
    return value


def require_run_field(run: dict[str, Any], field: str, expected: Any) -> None:
    if run.get(field) != expected:
        raise ReceiptBindingError(
            f"source run {field} must be {expected!r}, got {run.get(field)!r}"
        )


def select_artifact(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], str]:
    if not args.run_id.isdigit() or int(args.run_id) <= 0:
        raise ReceiptBindingError("source run id must be a positive integer")
    if args.run_attempt and (not args.run_attempt.isdigit() or int(args.run_attempt) <= 0):
        raise ReceiptBindingError("source run attempt must be a positive integer")
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise ReceiptBindingError("source commit must be a full lowercase hexadecimal SHA")
    expected = {
        "artex-main": ("cd-prod.yml", "push"),
        "artex-partner": ("cd-partner-prod.yml", "workflow_dispatch"),
    }
    if args.target not in expected or args.workflow != expected[args.target][0]:
        raise ReceiptBindingError("target and receipt workflow do not match")

    run = load_json_object(args.run_json, "source run")
    workflow = load_json_object(args.workflow_json, "workflow metadata")
    workflow_id = workflow.get("id")
    if not isinstance(workflow_id, int) or workflow_id <= 0:
        raise ReceiptBindingError("workflow metadata has no valid id")
    if str(run.get("id")) != args.run_id:
        raise ReceiptBindingError("source run id does not match API response")
    require_run_field(run, "status", "completed")
    require_run_field(run, "conclusion", "success")
    require_run_field(run, "event", expected[args.target][1])
    require_run_field(run, "head_branch", "main")
    require_run_field(run, "workflow_id", workflow_id)
    head_sha = require_string(run, "head_sha", "source run")
    if not COMMIT_RE.fullmatch(head_sha):
        raise ReceiptBindingError("source run head SHA is invalid")
    if args.target == "artex-main" and head_sha != args.source_commit:
        raise ReceiptBindingError("main source run head SHA does not match source commit")
    current_attempt = run.get("run_attempt")
    if not isinstance(current_attempt, int) or current_attempt <= 0:
        raise ReceiptBindingError("source run has no valid current attempt")
    if args.run_attempt and current_attempt < int(args.run_attempt):
        raise ReceiptBindingError("source run attempt is newer than the API response")

    try:
        artifacts = [json.loads(line) for line in Path(args.artifacts_jsonl).read_text(
            encoding="utf-8"
        ).splitlines() if line.strip()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptBindingError("could not read source artifacts") from exc
    prefix = f"artex-{args.target.removeprefix('artex-')}-receipt-"
    pattern = re.compile(
        re.escape(prefix + args.run_id + "-")
        + r"([0-9]+)-"
        + re.escape(args.source_commit)
    )
    matches = []
    now = datetime.now(timezone.utc)
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ReceiptBindingError("source artifact entry is not an object")
        name = artifact.get("name")
        if not isinstance(name, str):
            continue
        match = pattern.fullmatch(name)
        if not match:
            continue
        if args.run_attempt and match.group(1) != args.run_attempt:
            continue
        if artifact.get("expired") is not False:
            raise ReceiptBindingError("matching source artifact is expired or has unknown expiry")
        expires_at = artifact.get("expires_at")
        if not isinstance(expires_at, str):
            raise ReceiptBindingError("matching source artifact has no expiry timestamp")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReceiptBindingError("matching source artifact expiry is invalid") from exc
        if expiry <= now:
            raise ReceiptBindingError("matching source artifact is expired")
        matches.append((artifact, match.group(1)))
    if len(matches) != 1:
        raise ReceiptBindingError(
            f"expected exactly one unexpired matching receipt artifact, found {len(matches)}"
        )
    artifact, artifact_attempt = matches[0]
    artifact_id = artifact.get("id")
    if not isinstance(artifact_id, int) or artifact_id <= 0:
        raise ReceiptBindingError("source artifact has no valid id")
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReceiptBindingError("source artifact has no valid immutable digest")
    selection = {
        "artifact_id": artifact_id,
        "artifact_name": artifact["name"],
        "artifact_digest": digest,
        "source_run_id": args.run_id,
        "source_run_attempt": artifact_attempt,
        "workflow_id": workflow_id,
    }
    return selection, run, artifact_attempt


def read_receipt_zip(path: str, target: str, expected_digest: str) -> dict[str, Any]:
    try:
        payload = Path(path).read_bytes()
    except OSError as exc:
        raise ReceiptBindingError("could not read source artifact ZIP") from exc
    actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        raise ReceiptBindingError("downloaded artifact ZIP digest does not match GitHub metadata")
    expected_name = f"artex-{target.removeprefix('artex-')}-receipt.json"
    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) != 1 or entries[0].filename != expected_name:
                raise ReceiptBindingError("source artifact ZIP must contain only the expected receipt")
            entry = entries[0]
            if (
                entry.is_dir()
                or PurePosixPath(entry.filename).name != entry.filename
                or entry.file_size > MAX_RECEIPT_BYTES
            ):
                raise ReceiptBindingError("source artifact receipt path or size is unsafe")
            receipt_payload = archive.read(entry)
    except ReceiptBindingError:
        raise
    except (BadZipFile, OSError, RuntimeError) as exc:
        raise ReceiptBindingError("source artifact ZIP is invalid") from exc
    try:
        receipt: Any = json.loads(receipt_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptBindingError("source artifact receipt is invalid JSON") from exc
    if not isinstance(receipt, dict):
        raise ReceiptBindingError("source artifact receipt must be an object")
    return receipt


def bind_receipt(
    args: argparse.Namespace,
    selection: dict[str, Any],
    run: dict[str, Any],
    artifact_attempt: str,
) -> dict[str, Any]:
    receipt = read_receipt_zip(args.artifact_zip, args.target, selection["artifact_digest"])
    resolved = load_json_object(args.resolved_receipt, "resolved image receipt")
    expected = {
        "api_version": "delivery.kt/v1",
        "kind": "ImageDeploymentReceipt",
        "repository": "kt-security/ARTEX",
        "source_revision": args.source_commit,
        "target": args.target,
        "deployment_workflow": args.workflow,
        "deployment_run_id": args.run_id,
        "deployment_run_attempt": artifact_attempt,
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise ReceiptBindingError(f"source receipt {field} does not match the selected run")
    if receipt.get("image_ref") != resolved.get("image_ref"):
        raise ReceiptBindingError("source receipt image ref does not match registry resolution")
    if receipt.get("image_digest") != resolved.get("image_digest"):
        raise ReceiptBindingError("source receipt image digest does not match registry resolution")
    if not SHA256_RE.fullmatch(str(receipt.get("image_digest"))):
        raise ReceiptBindingError("source receipt image digest is invalid")
    verification = receipt.get("verification")
    if not isinstance(verification, dict) or verification.get("status") != "success":
        raise ReceiptBindingError("source receipt has no successful health verification")
    source_run_id = require_string(receipt, "source_run_id", "source receipt")
    source_run_attempt = require_string(receipt, "source_run_attempt", "source receipt")
    if not source_run_id.isdigit() or not source_run_attempt.isdigit():
        raise ReceiptBindingError("source receipt run identity is invalid")
    if args.target == "artex-main" and (
        source_run_id != args.run_id or source_run_attempt != artifact_attempt
    ):
        raise ReceiptBindingError("main receipt source run identity does not match its deployment")
    if run.get("conclusion") != "success":
        raise ReceiptBindingError("source run is not successful")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-json", required=True)
    parser.add_argument("--workflow-json", required=True)
    parser.add_argument("--artifacts-jsonl", required=True)
    parser.add_argument("--resolved-receipt", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True, choices=["artex-main", "artex-partner"])
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--artifact-zip")
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()
    try:
        selection, run, artifact_attempt = select_artifact(args)
        output: dict[str, Any] = selection
        if args.artifact_zip:
            output = bind_receipt(args, selection, run, artifact_attempt)
        Path(args.output_file).write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except ReceiptBindingError as exc:
        print(f"receipt binding failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
