#!/usr/bin/env python3
"""ARTEX delivery workflow and verifier tests; no credentials or production access."""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from zipfile import ZipFile

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFIER = ROOT / "scripts" / "verify_artex_deployment.py"
OLD_COMMIT = "0" * 40
NEW_COMMIT = "1" * 40
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMAGE_REF = f"oci.ktyun.cc/ktaiorg/artex@{DIGEST}"
EXPECTED_GO_SKIP = "^(TestStaticSedGeneratedInputAndBounds|TestGraphOverviewExpandsAssociatedCompanyScope|TestCVEEnrichCacheRoundtrip|TestInterceptApprovalFilters|TestCoreTaskLifecyclePG|TestInheritedActivityDetailAndRelationDeletion|TestLLMIdentityHTTPFlow|TestTaskMetadataPatchReturnsRenameAndPin|TestWorkerPoolSettingsRoundTrip)$|^TestCaptureApprovalLifecycle$/^(model_fallback|human_allow_tool_error|human_deny)$|^TestSideTaskArchiveVersions$/^[123]$"

sys.path.insert(0, str(ROOT / "scripts"))
import bind_artex_receipt as binder  # noqa: E402
import resolve_artex_image as resolver  # noqa: E402
import verify_artex_deployment as deployment_verifier  # noqa: E402


def load_workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def run_commands(workflow: dict) -> str:
    return "\n".join(
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    )


class WorkflowDeliveryTest(unittest.TestCase):
    def test_pr_ci_is_read_only_and_runs_all_go_packages(self) -> None:
        ci = load_workflow("ci.yml")
        self.assertIn("pull_request", ci[True])
        self.assertNotIn("push", ci[True])
        self.assertEqual(ci["permissions"], {"contents": "read"})
        self.assertEqual(ci["jobs"]["verify"]["env"]["GO_TEST_SKIP"], EXPECTED_GO_SKIP)
        serialized = yaml.safe_dump(ci)
        for forbidden in (
            "id-token",
            "secrets.",
            "CD_WEBHOOK",
            "CD_TLS_CA",
            "docker push",
            "buildx build",
            "artex-main",
            "artex-partner",
            "artex-both",
            "environment:",
            "packages=()",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)
        commands = run_commands(ci)
        for required in (
            "npm ci --no-audit --no-fund",
            "npm run build:static",
            'go test -p=1 -count=1 -skip "${GO_TEST_SKIP}" ./...',
            "go test ./server -run '^TestHealthReportsFullBuildRevision$' -count=1",
            "go vet ./...",
            "go build ./...",
            "-X main.version=${SOURCE_COMMIT}",
            "scripts/verify_artex_deployment.py",
            "--allow-http-loopback",
            '-addr "127.0.0.1:${http_port}"',
            "python3 -m unittest discover -s scripts -p 'test_*.py'",
            "actionlint@v1.7.12",
            ".github/workflows/rollback-prod.yml",
            "shellcheck scripts/*.sh",
            "CD_HEALTH_CA_PUBLIC",
        ):
            with self.subTest(required=required):
                self.assertIn(required, commands + serialized)

    def test_main_builds_once_and_creates_run_bound_receipt_after_https_health(self) -> None:
        workflow = load_workflow("cd-prod.yml")
        self.assertEqual(workflow[True]["push"]["branches"], ["main"])
        self.assertNotIn("workflow_dispatch", workflow[True])
        self.assertEqual(workflow["permissions"], {"contents": "read", "id-token": "write"})
        job = workflow["jobs"]["build-deploy-main"]
        self.assertEqual(job["env"]["GO_TEST_SKIP"], EXPECTED_GO_SKIP)
        commands = run_commands(workflow)
        self.assertEqual(commands.count("docker buildx build"), 1)
        self.assertEqual(commands.count("-X main.version=${GITHUB_SHA}"), 1)
        self.assertIn("repository:ktaiorg/artex:pull,push", commands)
        self.assertIn('--cacert "${ca_file}"', commands)
        self.assertIn('CD_TLS_CA: ${{ secrets.CD_TLS_CA }}', yaml.safe_dump(job))
        self.assertIn('--expected-commit "${GITHUB_SHA}"', commands)
        self.assertIn('--ca-file "${ca_file}"', commands)
        self.assertIn('go test -p=1 -count=1 -skip "${GO_TEST_SKIP}" ./...', commands)
        self.assertIn("shellcheck scripts/*.sh", commands)
        self.assertIn("source_run_id", commands)
        self.assertIn("source_run_attempt", commands)
        self.assertIn("deployment_run_id", commands)
        self.assertIn('verification: {status: "success"}', commands)
        upload = next(step for step in job["steps"] if step.get("name") == "Upload main deployment receipt")
        self.assertEqual(
            upload["with"]["name"],
            "artex-main-receipt-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}",
        )
        health_position = commands.index('--base-url "${CD_VERIFY_BASE_URL}"')
        receipt_position = commands.index("source_run_id")
        self.assertLess(health_position, receipt_position)
        for forbidden in (
            "artex-both",
            "artex-partner",
            "--insecure",
            "packages=()",
            "http://69.194.14.91:52913",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, commands)

    def test_partner_binds_successful_main_receipt_and_never_builds(self) -> None:
        workflow = load_workflow("cd-partner-prod.yml")
        inputs = workflow[True]["workflow_dispatch"]["inputs"]
        self.assertTrue(inputs["source_run_id"]["required"])
        self.assertIn("source_run_attempt", inputs)
        self.assertEqual(
            workflow["permissions"],
            {"actions": "read", "contents": "read", "id-token": "write"},
        )
        serialized = yaml.safe_dump(workflow)
        commands = run_commands(workflow)
        for forbidden in (
            "setup-go",
            "setup-node",
            "go build",
            "go test",
            "npm ",
            "docker build",
            "buildx build",
            "docker push",
            "pull,push",
            "artex-both",
            "--insecure",
            "--allow-http-loopback",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)
        for required in (
            "git merge-base --is-ancestor",
            "repository:ktaiorg/artex:pull",
            "scripts/resolve_artex_image.py",
            "scripts/fetch_artex_receipt.sh",
            "--workflow cd-prod.yml",
            "--target artex-main",
            '"artex-partner"',
            '--expected-commit "${SOURCE_COMMIT}"',
            '--cacert "${ca_file}"',
            '--ca-file "${ca_file}"',
            "artex-main-bound-receipt.json",
            "artex-partner-receipt-${{ github.run_id }}-${{ github.run_attempt }}",
        ):
            with self.subTest(required=required):
                self.assertIn(required, commands + serialized)
        resolve_position = commands.index("scripts/resolve_artex_image.py")
        bind_position = commands.index("scripts/fetch_artex_receipt.sh")
        main_verify_position = commands.index('--base-url "${CD_MAIN_VERIFY_BASE_URL}"')
        partner_webhook_position = commands.index('body=$(jq -cn --arg target "artex-partner"')
        partner_verify_position = commands.index('--base-url "${CD_PARTNER_VERIFY_BASE_URL}"')
        partner_receipt_position = commands.index('.target = "artex-partner"')
        self.assertLess(resolve_position, bind_position)
        self.assertLess(bind_position, main_verify_position)
        self.assertLess(main_verify_position, partner_webhook_position)
        self.assertLess(partner_verify_position, partner_receipt_position)

    def test_rollback_uses_environment_receipt_digest_and_https_health(self) -> None:
        workflow = load_workflow("rollback-prod.yml")
        self.assertEqual(list(workflow[True]), ["workflow_dispatch"])
        inputs = workflow[True]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["target"]["options"], ["artex-main", "artex-partner"])
        for name in ("target", "receipt_run_id", "source_commit", "image", "reason"):
            self.assertTrue(inputs[name]["required"])
        job = workflow["jobs"]["rollback"]
        self.assertEqual(job["if"], "${{ github.ref == 'refs/heads/main' }}")
        self.assertEqual(
            job["environment"],
            "${{ inputs.target == 'artex-main' && 'production' || 'production-partner' }}",
        )
        serialized = yaml.safe_dump(workflow)
        commands = run_commands(workflow)
        for forbidden in (
            "docker build",
            "buildx build",
            "docker push",
            "pull,push",
            "--insecure",
            "--allow-http-loopback",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)
        for required in (
            "source_workflow=cd-prod.yml",
            "source_workflow=cd-partner-prod.yml",
            "scripts/resolve_artex_image.py",
            "scripts/fetch_artex_receipt.sh",
            "immutable_ref=$(jq -er '.image_ref'",
            '--cacert "${ca_file}"',
            '--ca-file "${ca_file}"',
            "ImageRollbackReceipt",
            "verification: {status: \"success\"}",
        ):
            with self.subTest(required=required):
                self.assertIn(required, commands)
        webhook_position = commands.index("Rollback webhook")
        health_position = commands.index('python3 scripts/verify_artex_deployment.py')
        receipt_position = commands.index("ImageRollbackReceipt")
        self.assertLess(webhook_position, health_position)
        self.assertLess(health_position, receipt_position)

    def test_tokens_never_cross_step_boundaries(self) -> None:
        for name in ("cd-prod.yml", "cd-partner-prod.yml", "rollback-prod.yml"):
            workflow = load_workflow(name)
            for line in run_commands(workflow).splitlines():
                if "GITHUB_OUTPUT" in line:
                    self.assertNotRegex(line, r"(?i)(oidc|token|\bTOK\b)")
            self.assertNotIn("steps.zot.outputs", yaml.safe_dump(workflow))

    def test_delivery_concurrency_serializes_all_mutating_workflows(self) -> None:
        for name in ("cd-prod.yml", "cd-partner-prod.yml", "rollback-prod.yml"):
            workflow = load_workflow(name)
            self.assertEqual(workflow["concurrency"]["group"], "artex-production")
            self.assertFalse(workflow["concurrency"]["cancel-in-progress"])

    def test_modified_workflows_use_current_action_majors(self) -> None:
        for name in ("ci.yml", "cd-prod.yml", "cd-partner-prod.yml", "rollback-prod.yml"):
            workflow = load_workflow(name)
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    action = step.get("uses", "")
                    if not action:
                        continue
                    with self.subTest(workflow=name, action=action):
                        if action.startswith("actions/"):
                            self.assertRegex(action, "@v7$")
                        elif action == "docker/setup-buildx-action@v4":
                            pass
                        else:
                            self.fail(f"unexpected action: {action}")


class ImageResolverTest(unittest.TestCase):
    def test_accepts_matching_tag_and_digest(self) -> None:
        tag = f"oci.ktyun.cc/ktaiorg/artex:prod-sha-{NEW_COMMIT[:10]}"
        digest = f"oci.ktyun.cc/ktaiorg/artex@sha256:{'a' * 64}"
        self.assertEqual(
            resolver.parse_image_reference(tag, NEW_COMMIT),
            ("tag", f"prod-sha-{NEW_COMMIT[:10]}"),
        )
        self.assertEqual(
            resolver.parse_image_reference(digest, NEW_COMMIT),
            ("digest", f"sha256:{'a' * 64}"),
        )

    def test_rejects_mutable_or_mismatched_references(self) -> None:
        for image in (
            "oci.ktyun.cc/ktaiorg/artex:latest",
            "oci.ktyun.cc/ktaiorg/other:prod-sha-" + NEW_COMMIT[:10],
            "oci.ktyun.cc/ktaiorg/artex:prod-sha-" + OLD_COMMIT[:10],
            "oci.ktyun.cc/ktaiorg/artex@sha256:not-a-digest",
        ):
            with self.subTest(image=image):
                with self.assertRaises(resolver.ImageResolutionError):
                    resolver.parse_image_reference(image, NEW_COMMIT)

    def test_selects_linux_amd64_manifest(self) -> None:
        digest = "sha256:" + "b" * 64
        document = {
            "manifests": [
                {"digest": "sha256:" + "c" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": digest, "platform": {"os": "linux", "architecture": "amd64"}},
            ]
        }
        self.assertEqual(resolver.select_amd64_manifest(document), digest)
        self.assertIsNone(resolver.select_amd64_manifest({"config": {}}))

    def test_reads_oci_revision_label(self) -> None:
        config = {"config": {"Labels": {"org.opencontainers.image.revision": NEW_COMMIT}}}
        self.assertEqual(resolver.source_revision(config), NEW_COMMIT)
        with self.assertRaises(resolver.ImageResolutionError):
            resolver.source_revision({"config": {"Labels": {}}})

    def make_registry(self, config: dict | None = None, index: bool = False):
        if config is None:
            config = {
                "os": "linux",
                "architecture": "amd64",
                "config": {"Labels": {"org.opencontainers.image.revision": NEW_COMMIT}},
            }

        class FakeRegistryClient:
            def __init__(self) -> None:
                self.config_payload = json.dumps(config).encode("utf-8")
                self.config_digest = resolver.payload_digest(self.config_payload)
                self.manifest_payload = json.dumps(
                    {"config": {"digest": self.config_digest}}
                ).encode("utf-8")
                self.manifest_digest = resolver.payload_digest(self.manifest_payload)
                self.index_payload = json.dumps(
                    {
                        "manifests": [
                            {
                                "digest": self.manifest_digest,
                                "platform": {"os": "linux", "architecture": "amd64"},
                            }
                        ]
                    }
                ).encode("utf-8")
                self.index_digest = resolver.payload_digest(self.index_payload)

            def get(self, reference: str):
                if index and reference in {f"prod-sha-{NEW_COMMIT[:10]}", self.index_digest}:
                    return self.index_payload, self.index_digest
                if not index and reference in {
                    f"prod-sha-{NEW_COMMIT[:10]}",
                    self.manifest_digest,
                }:
                    return self.manifest_payload, self.manifest_digest
                if index and reference == self.manifest_digest:
                    return self.manifest_payload, self.manifest_digest
                raise AssertionError(f"unexpected manifest reference: {reference}")

            def blob(self, digest: str) -> bytes:
                if digest != self.config_digest:
                    raise AssertionError(f"unexpected config digest: {digest}")
                return self.config_payload

        return FakeRegistryClient()

    def test_resolves_existing_single_manifest_and_index(self) -> None:
        tag = f"oci.ktyun.cc/ktaiorg/artex:prod-sha-{NEW_COMMIT[:10]}"
        for index in (False, True):
            with self.subTest(index=index):
                registry = self.make_registry(index=index)
                receipt = resolver.resolve_image(registry, tag, NEW_COMMIT)
                expected = registry.index_digest if index else registry.manifest_digest
                self.assertEqual(receipt["image_digest"], expected)
                self.assertEqual(receipt["source_revision"], NEW_COMMIT)

    def test_rejects_corrupt_nested_manifest_or_config(self) -> None:
        tag = f"oci.ktyun.cc/ktaiorg/artex:prod-sha-{NEW_COMMIT[:10]}"
        for artifact in ("manifest_payload", "config_payload"):
            with self.subTest(artifact=artifact):
                registry = self.make_registry(index=True)
                setattr(registry, artifact, b"{}")
                with self.assertRaisesRegex(resolver.ImageResolutionError, "digest"):
                    resolver.resolve_image(registry, tag, NEW_COMMIT)

    def test_rejects_wrong_platform_or_source_revision(self) -> None:
        tag = f"oci.ktyun.cc/ktaiorg/artex:prod-sha-{NEW_COMMIT[:10]}"
        for field, value, message in (
            ("architecture", "arm64", "linux/amd64"),
            ("os", "windows", "linux/amd64"),
        ):
            with self.subTest(field=field):
                config = {
                    "os": "linux",
                    "architecture": "amd64",
                    "config": {"Labels": {"org.opencontainers.image.revision": NEW_COMMIT}},
                    field: value,
                }
                with self.assertRaisesRegex(resolver.ImageResolutionError, message):
                    resolver.resolve_image(self.make_registry(config), tag, NEW_COMMIT)
        config = {
            "os": "linux",
            "architecture": "amd64",
            "config": {"Labels": {"org.opencontainers.image.revision": OLD_COMMIT}},
        }
        with self.assertRaisesRegex(resolver.ImageResolutionError, "revision"):
            resolver.resolve_image(self.make_registry(config), tag, NEW_COMMIT)


class ReceiptBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.run = {
            "id": 12345,
            "run_attempt": 2,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "head_branch": "main",
            "head_sha": NEW_COMMIT,
            "workflow_id": 678,
        }
        self.workflow = {"id": 678}
        self.receipt = {
            "api_version": "delivery.kt/v1",
            "kind": "ImageDeploymentReceipt",
            "repository": "kt-security/ARTEX",
            "source_revision": NEW_COMMIT,
            "source_run_id": "12345",
            "source_run_attempt": "2",
            "deployment_workflow": "cd-prod.yml",
            "deployment_run_id": "12345",
            "deployment_run_attempt": "2",
            "image_ref": IMAGE_REF,
            "image_tag": f"prod-sha-{NEW_COMMIT[:10]}",
            "image_digest": DIGEST,
            "target": "artex-main",
            "verification": {"status": "success"},
        }
        self.resolved = {
            "image_ref": IMAGE_REF,
            "image_digest": DIGEST,
            "source_revision": NEW_COMMIT,
        }
        self.zip_path = self.root / "receipt.zip"
        self._write_zip()
        self.artifact = {
            "id": 999,
            "name": f"artex-main-receipt-12345-2-{NEW_COMMIT}",
            "expired": False,
            "expires_at": "2099-01-01T00:00:00Z",
            "digest": self._zip_digest(),
        }
        self.args = argparse.Namespace(
            run_id="12345",
            run_attempt=None,
            source_commit=NEW_COMMIT,
            target="artex-main",
            workflow="cd-prod.yml",
            run_json=str(self.root / "run.json"),
            workflow_json=str(self.root / "workflow.json"),
            artifacts_jsonl=str(self.root / "artifacts.jsonl"),
            resolved_receipt=str(self.root / "resolved.json"),
            artifact_zip=str(self.zip_path),
        )
        self._write_metadata()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_zip(self) -> None:
        with ZipFile(self.zip_path, "w") as archive:
            archive.writestr("artex-main-receipt.json", json.dumps(self.receipt))

    def _zip_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.zip_path.read_bytes()).hexdigest()

    def _write_metadata(self) -> None:
        Path(self.args.run_json).write_text(json.dumps(self.run), encoding="utf-8")
        Path(self.args.workflow_json).write_text(json.dumps(self.workflow), encoding="utf-8")
        Path(self.args.artifacts_jsonl).write_text(json.dumps(self.artifact) + "\n", encoding="utf-8")
        Path(self.args.resolved_receipt).write_text(json.dumps(self.resolved), encoding="utf-8")

    def _bind(self) -> dict:
        selection, run, attempt = binder.select_artifact(self.args)
        return binder.bind_receipt(self.args, selection, run, attempt)

    def test_binds_run_attempt_artifact_digest_commit_and_image(self) -> None:
        bound = self._bind()
        self.assertEqual(bound, self.receipt)
        selection, _, attempt = binder.select_artifact(self.args)
        self.assertEqual(selection["artifact_id"], 999)
        self.assertEqual(selection["artifact_digest"], self._zip_digest())
        self.assertEqual(attempt, "2")

    def test_rejects_same_commit_with_different_registry_digest(self) -> None:
        self.resolved["image_digest"] = OTHER_DIGEST
        self.resolved["image_ref"] = f"oci.ktyun.cc/ktaiorg/artex@{OTHER_DIGEST}"
        self._write_metadata()
        with self.assertRaisesRegex(binder.ReceiptBindingError, "does not match"):
            self._bind()

    def test_rejects_wrong_run_state_event_branch_commit_and_workflow(self) -> None:
        mutations = (
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("event", "workflow_dispatch"),
            ("head_branch", "feature"),
            ("head_sha", OLD_COMMIT),
            ("workflow_id", 1),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                original = self.run[field]
                self.run[field] = value
                self._write_metadata()
                with self.assertRaises(binder.ReceiptBindingError):
                    self._bind()
                self.run[field] = original
                self._write_metadata()

    def test_rejects_expired_duplicate_and_wrong_artifact_digest(self) -> None:
        self.artifact["expired"] = True
        self._write_metadata()
        with self.assertRaisesRegex(binder.ReceiptBindingError, "expired"):
            self._bind()
        self.artifact["expired"] = False
        self.artifact["digest"] = OTHER_DIGEST
        self._write_metadata()
        with self.assertRaisesRegex(binder.ReceiptBindingError, "ZIP digest"):
            self._bind()
        self.artifact["digest"] = self._zip_digest()
        self._write_metadata()
        Path(self.args.artifacts_jsonl).write_text(
            json.dumps(self.artifact) + "\n" + json.dumps(self.artifact) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(binder.ReceiptBindingError, "exactly one"):
            self._bind()

    def test_rejects_wrong_receipt_run_commit_target_or_health(self) -> None:
        mutations = (
            ("deployment_run_id", "54321"),
            ("source_revision", OLD_COMMIT),
            ("target", "artex-partner"),
            ("verification", {"status": "failed"}),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                original = self.receipt[field]
                self.receipt[field] = value
                self._write_zip()
                self.artifact["digest"] = self._zip_digest()
                self._write_metadata()
                with self.assertRaises(binder.ReceiptBindingError):
                    self._bind()
                self.receipt[field] = original
                self._write_zip()
                self.artifact["digest"] = self._zip_digest()
                self._write_metadata()

    def test_rejects_unsafe_or_mismatched_zip_content(self) -> None:
        with ZipFile(self.zip_path, "w") as archive:
            archive.writestr("../artex-main-receipt.json", json.dumps(self.receipt))
        self.artifact["digest"] = self._zip_digest()
        self._write_metadata()
        with self.assertRaisesRegex(binder.ReceiptBindingError, "expected receipt"):
            self._bind()


class DeploymentHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/api/health":
            self.send_response(404)
            self.end_headers()
            return
        if self.server.redirect_target:
            self.server.redirect_requests += 1
            self.send_response(302)
            self.send_header("Location", self.server.redirect_target)
            self.end_headers()
            return
        index = min(self.server.version_requests, len(self.server.versions) - 1)
        self.server.version_requests += 1
        self.send_response(self.server.health_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.server.health_status == 200:
            body = json.dumps(
                {"ok": True, "service": "artex", "version": self.server.versions[index]}
            ).encode("utf-8")
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class DeploymentVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cert_dir = tempfile.TemporaryDirectory()
        root = Path(cls.cert_dir.name)
        cls.ca_file = root / "ca.pem"
        key_file = root / "server.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                "-keyout", str(key_file), "-out", str(cls.ca_file),
            ],
            check=True,
            capture_output=True,
        )
        cls.wrong_ca_file = root / "wrong.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=wrong", "-keyout", str(root / "wrong.key"),
                "-out", str(cls.wrong_ca_file),
            ],
            check=True,
            capture_output=True,
        )
        cls.key_file = key_file

    @classmethod
    def tearDownClass(cls) -> None:
        cls.cert_dir.cleanup()

    def setUp(self) -> None:
        self.http_server = self._start_server(False)
        self.https_server = self._start_server(True)
        self.base_url = f"http://127.0.0.1:{self.http_server.server_port}"
        self.https_url = f"https://127.0.0.1:{self.https_server.server_port}"

    def tearDown(self) -> None:
        for server in (self.http_server, self.https_server):
            server.shutdown()
            server.server_close()
            server.thread.join(timeout=2)

    def _start_server(self, use_tls: bool) -> ThreadingHTTPServer:
        server = ThreadingHTTPServer(("127.0.0.1", 0), DeploymentHandler)
        server.daemon_threads = True
        server.health_status = 200
        server.versions = [NEW_COMMIT]
        server.version_requests = 0
        server.redirect_target = None
        server.redirect_requests = 0
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.ca_file, self.key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        server.thread = threading.Thread(target=server.serve_forever, daemon=True)
        server.thread.start()
        return server

    def run_verifier(
        self,
        base_url: str | None = None,
        timeout: float = 0.5,
        ca_file: Path | None | object = ...,
        allow_http: bool = False,
    ) -> subprocess.CompletedProcess:
        command = [
            sys.executable,
            str(VERIFIER),
            "--base-url",
            base_url or self.base_url,
            "--expected-commit",
            NEW_COMMIT,
            "--timeout",
            str(timeout),
            "--interval",
            "0.01",
            "--request-timeout",
            "0.1",
        ]
        if ca_file is ...:
            ca_file = self.ca_file if (base_url or self.base_url).startswith("https") else None
        if ca_file is not None:
            command.extend(["--ca-file", str(ca_file)])
        if allow_http:
            command.append("--allow-http-loopback")
        return subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)

    def test_loopback_smoke_old_version_eventually_becomes_expected_commit(self) -> None:
        self.http_server.versions = [OLD_COMMIT, OLD_COMMIT, NEW_COMMIT]
        result = self.run_verifier(allow_http=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"version={NEW_COMMIT}", result.stdout)
        self.assertGreaterEqual(self.http_server.version_requests, 3)

    def test_http_and_non_loopback_http_are_rejected(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 1)
        self.assertIn("require HTTPS", result.stderr)
        with self.assertRaises(deployment_verifier.DeploymentVerificationError):
            deployment_verifier.validate_base_url("http://example.com", True)

    def test_https_with_pinned_ca_succeeds(self) -> None:
        result = self.run_verifier(self.https_url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"version={NEW_COMMIT}", result.stdout)

    def test_https_requires_ca_and_rejects_wrong_ca(self) -> None:
        missing = self.run_verifier(self.https_url, ca_file=None)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("--ca-file is required", missing.stderr)
        wrong = self.run_verifier(self.https_url, timeout=0.08, ca_file=self.wrong_ca_file)
        self.assertEqual(wrong.returncode, 1)
        self.assertIn("before timeout", wrong.stderr)
        self.assertIn("certificate", wrong.stderr.lower())

    def test_https_to_http_redirect_is_rejected_without_following(self) -> None:
        self.https_server.redirect_target = self.base_url + "/api/health"
        result = self.run_verifier(self.https_url, timeout=0.08)
        self.assertEqual(result.returncode, 1)
        self.assertIn("redirect refused", result.stderr)
        self.assertGreater(self.https_server.redirect_requests, 0)
        self.assertEqual(self.http_server.version_requests, 0)

    def test_unhealthy_endpoint_fails_closed(self) -> None:
        self.https_server.health_status = 503
        result = self.run_verifier(self.https_url, timeout=0.08)
        self.assertEqual(result.returncode, 1)
        self.assertIn("before timeout", result.stderr)
        self.assertIn("HTTP 503", result.stderr)

    def test_stale_version_times_out_with_failure(self) -> None:
        self.https_server.versions = [OLD_COMMIT]
        result = self.run_verifier(self.https_url, timeout=0.08)
        self.assertEqual(result.returncode, 1)
        self.assertIn("before timeout", result.stderr)
        self.assertIn(f"last observed version={OLD_COMMIT}", result.stderr)


if __name__ == "__main__":
    unittest.main()
