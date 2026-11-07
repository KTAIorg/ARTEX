#!/usr/bin/env python3
"""ARTEX delivery workflow and verifier tests; no credentials or production access."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
VERIFIER = ROOT / "scripts" / "verify_artex_deployment.py"
OLD_COMMIT = "0" * 40
NEW_COMMIT = "1" * 40

sys.path.insert(0, str(ROOT / "scripts"))
import resolve_artex_image as resolver  # noqa: E402


def load_workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def run_commands(workflow: dict) -> str:
    return "\n".join(
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    )


class WorkflowDeliveryTest(unittest.TestCase):
    def test_pr_ci_is_read_only_and_has_no_delivery_credentials(self) -> None:
        ci = load_workflow("ci.yml")
        self.assertIn("pull_request", ci[True])
        self.assertNotIn("push", ci[True])
        self.assertEqual(ci["permissions"], {"contents": "read"})
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
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)
        commands = run_commands(ci)
        for required in (
            "npm ci --no-audit --no-fund",
            "npm run build:static",
            "go test -p=1 -count=1 -skip '^TestStaticSedGeneratedInputAndBounds$' \"${packages[@]}\"",
            "go test ./server -run '^TestHealthReportsFullBuildRevision$' -count=1",
            "github.com/Autumn-27/artex/agent|github.com/Autumn-27/artex/db|github.com/Autumn-27/artex/server",
            "go vet ./...",
            "go build ./...",
            "-X main.version=${SOURCE_COMMIT}",
            "scripts/verify_artex_deployment.py",
            '-addr "127.0.0.1:${http_port}"',
            "python3 -m unittest discover -s scripts -p 'test_*.py'",
            "actionlint@v1.7.12",
        ):
            with self.subTest(required=required):
                self.assertIn(required, commands)

    def test_main_builds_once_deploys_only_main_and_verifies_full_sha(self) -> None:
        workflow = load_workflow("cd-prod.yml")
        self.assertEqual(workflow[True]["push"]["branches"], ["main"])
        self.assertNotIn("workflow_dispatch", workflow[True])
        self.assertEqual(
            workflow["permissions"], {"contents": "read", "id-token": "write"}
        )
        job = workflow["jobs"]["build-deploy-main"]
        self.assertEqual(
            job["if"],
            "${{ github.ref == 'refs/heads/main' && github.event_name == 'push' }}",
        )
        commands = run_commands(workflow)
        self.assertEqual(commands.count("docker buildx build"), 1)
        self.assertEqual(commands.count("-X main.version=${GITHUB_SHA}"), 1)
        self.assertIn("repository:ktaiorg/artex:pull,push", commands)
        self.assertIn('--cacert "${ca_file}"', commands)
        self.assertIn('CD_TLS_CA: ${{ secrets.CD_TLS_CA }}', yaml.safe_dump(job))
        self.assertIn('--expected-commit "${GITHUB_SHA}"', commands)
        self.assertIn('"artex-main"', commands)
        self.assertIn('"${image_repository}@${digest}"', commands)
        for forbidden in (
            "artex-both",
            "artex-partner",
            "--insecure",
            "CD_WEBHOOK_URL:-",
            "http://69.194.14.91:39876",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, commands)

    def test_partner_promotion_never_builds_and_uses_pull_only(self) -> None:
        workflow = load_workflow("cd-partner-prod.yml")
        self.assertEqual(list(workflow[True]), ["workflow_dispatch"])
        self.assertEqual(
            workflow["permissions"], {"contents": "read", "id-token": "write"}
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
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)
        for required in (
            "git merge-base --is-ancestor",
            "repository:ktaiorg/artex:pull",
            "scripts/resolve_artex_image.py",
            '"artex-partner"',
            '--expected-commit "${SOURCE_COMMIT}"',
            '--cacert "${ca_file}"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, commands)
        self.assertLess(
            commands.index("git merge-base --is-ancestor"),
            commands.index("scripts/resolve_artex_image.py"),
        )
        resolve_position = commands.index("scripts/resolve_artex_image.py")
        main_verify_position = commands.index('--base-url "${CD_MAIN_VERIFY_BASE_URL}"')
        partner_webhook_position = commands.index(
            'body=$(jq -cn --arg target "artex-partner"'
        )
        self.assertLess(resolve_position, main_verify_position)
        self.assertLess(main_verify_position, partner_webhook_position)

    def test_tokens_never_cross_step_boundaries(self) -> None:
        for name in ("cd-prod.yml", "cd-partner-prod.yml"):
            workflow = load_workflow(name)
            for line in run_commands(workflow).splitlines():
                if "GITHUB_OUTPUT" in line:
                    self.assertNotRegex(line, r"(?i)(oidc|token|\bTOK\b)")
            self.assertNotIn("steps.zot.outputs", yaml.safe_dump(workflow))

    def test_delivery_concurrency_serializes_both_targets(self) -> None:
        main = load_workflow("cd-prod.yml")
        partner = load_workflow("cd-partner-prod.yml")
        self.assertEqual(main["concurrency"]["group"], "artex-production")
        self.assertEqual(partner["concurrency"]["group"], "artex-production")
        self.assertFalse(main["concurrency"]["cancel-in-progress"])
        self.assertFalse(partner["concurrency"]["cancel-in-progress"])

    def test_modified_workflows_use_current_action_majors(self) -> None:
        for name in ("ci.yml", "cd-prod.yml", "cd-partner-prod.yml"):
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


class DeploymentHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/api/health":
            self.send_response(404)
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
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), DeploymentHandler)
        self.server.daemon_threads = True
        self.server.health_status = 200
        self.server.versions = [NEW_COMMIT]
        self.server.version_requests = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def run_verifier(self, timeout: float = 0.5) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--base-url",
                self.base_url,
                "--expected-commit",
                NEW_COMMIT,
                "--timeout",
                str(timeout),
                "--interval",
                "0.01",
                "--request-timeout",
                "0.1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_old_version_eventually_becomes_expected_commit(self) -> None:
        self.server.versions = [OLD_COMMIT, OLD_COMMIT, NEW_COMMIT]
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"version={NEW_COMMIT}", result.stdout)
        self.assertGreaterEqual(self.server.version_requests, 3)

    def test_stale_version_times_out_with_failure(self) -> None:
        self.server.versions = [OLD_COMMIT]
        result = self.run_verifier(timeout=0.08)
        self.assertEqual(result.returncode, 1)
        self.assertIn("before timeout", result.stderr)
        self.assertIn(f"last observed version={OLD_COMMIT}", result.stderr)

    def test_unhealthy_endpoint_fails_closed(self) -> None:
        self.server.health_status = 503
        result = self.run_verifier(timeout=0.08)
        self.assertEqual(result.returncode, 1)
        self.assertIn("before timeout", result.stderr)
        self.assertIn("HTTP 503", result.stderr)


if __name__ == "__main__":
    unittest.main()
