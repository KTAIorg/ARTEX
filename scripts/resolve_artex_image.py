#!/usr/bin/env python3
"""Resolve an existing ARTEX OCI artifact and verify its source revision label."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


IMAGE_REPOSITORY = "oci.ktyun.cc/ktaiorg/artex"
REGISTRY_REPOSITORY = "ktaiorg/artex"
ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class ImageResolutionError(RuntimeError):
    pass


def parse_image_reference(image: str, source_commit: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ImageResolutionError("source commit must be a full lowercase hexadecimal SHA")
    match = re.fullmatch(
        re.escape(IMAGE_REPOSITORY) + r"(?::(prod-sha-[0-9a-f]{10})|@(sha256:[0-9a-f]{64}))",
        image,
    )
    if not match:
        raise ImageResolutionError(
            f"image must be {IMAGE_REPOSITORY}:prod-sha-<short10> or {IMAGE_REPOSITORY}@sha256:<digest>"
        )
    tag, digest = match.groups()
    if tag is not None and tag != f"prod-sha-{source_commit[:10]}":
        raise ImageResolutionError("image tag does not match source commit")
    return ("tag", tag) if tag is not None else ("digest", digest)


def select_amd64_manifest(document: dict[str, Any]) -> str | None:
    manifests = document.get("manifests")
    if manifests is None:
        return None
    if not isinstance(manifests, list):
        raise ImageResolutionError("registry returned an invalid manifest index")
    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        platform = manifest.get("platform", {})
        digest = manifest.get("digest")
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
            and isinstance(digest, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        ):
            return digest
    raise ImageResolutionError("image index does not contain a linux/amd64 manifest")


def source_revision(config: dict[str, Any]) -> str:
    for section in ("config", "container_config"):
        value = config.get(section)
        if isinstance(value, dict):
            labels = value.get("Labels")
            if isinstance(labels, dict):
                revision = labels.get("org.opencontainers.image.revision")
                if isinstance(revision, str):
                    return revision
    raise ImageResolutionError("image config has no OCI source revision label")


class RegistryClient:
    def __init__(self, token: str, timeout: float) -> None:
        self.token = token
        self.timeout = timeout

    def get(self, reference: str, accept: str = ACCEPT) -> tuple[bytes, str | None]:
        url = f"https://oci.ktyun.cc/v2/{REGISTRY_REPOSITORY}/manifests/{reference}"
        return self._request(url, accept)

    def blob(self, digest: str) -> bytes:
        url = f"https://oci.ktyun.cc/v2/{REGISTRY_REPOSITORY}/blobs/{digest}"
        payload, _ = self._request(url, "application/octet-stream")
        return payload

    def _request(self, url: str, accept: str) -> tuple[bytes, str | None]:
        request = Request(
            url,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "artex-image-resolver/1.0",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise ImageResolutionError(f"registry returned HTTP {response.status}")
                return response.read(), response.headers.get("Docker-Content-Digest")
        except OSError as exc:
            raise ImageResolutionError(f"registry request failed: {exc}") from exc


def decode_json_object(payload: bytes, description: str) -> dict[str, Any]:
    try:
        document: Any = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageResolutionError(f"registry returned invalid {description} JSON") from exc
    if not isinstance(document, dict):
        raise ImageResolutionError(f"registry {description} is not an object")
    return document


def payload_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def resolve_image(
    client: RegistryClient,
    image: str,
    expected_commit: str,
) -> dict[str, str]:
    kind, reference = parse_image_reference(image, expected_commit)
    payload, registry_digest = client.get(reference)
    computed_digest = payload_digest(payload)
    digest = registry_digest or computed_digest
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ImageResolutionError("registry returned an invalid digest")
    if kind == "digest" and digest != reference:
        raise ImageResolutionError("registry digest does not match requested digest")
    if registry_digest is not None and registry_digest != computed_digest:
        raise ImageResolutionError("registry digest does not match manifest content")

    manifest = decode_json_object(payload, "manifest")
    amd64_digest = select_amd64_manifest(manifest)
    if amd64_digest is not None:
        payload, registry_digest = client.get(amd64_digest)
        if payload_digest(payload) != amd64_digest or registry_digest not in {
            None,
            amd64_digest,
        }:
            raise ImageResolutionError("amd64 manifest digest does not match its content")
        manifest = decode_json_object(payload, "amd64 manifest")

    config_section = manifest.get("config")
    if not isinstance(config_section, dict):
        raise ImageResolutionError("image manifest has no config object")
    config_digest = config_section.get("digest")
    if not isinstance(config_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest):
        raise ImageResolutionError("image manifest has no valid config digest")
    config_payload = client.blob(config_digest)
    if payload_digest(config_payload) != config_digest:
        raise ImageResolutionError("image config digest does not match its content")
    config = decode_json_object(config_payload, "image config")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ImageResolutionError("image config does not target linux/amd64")
    if source_revision(config) != expected_commit:
        raise ImageResolutionError("image OCI revision does not match source commit")

    return {
        "api_version": "delivery.kt/v1",
        "kind": "ImageDeploymentReceipt",
        "repository": "kt-security/ARTEX",
        "source_revision": expected_commit,
        "input_image": image,
        "image_ref": f"{IMAGE_REPOSITORY}@{digest}",
        "image_digest": digest,
        "target": "artex-partner",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    token = os.environ.get("REGISTRY_TOKEN", "")
    if not token:
        print("REGISTRY_TOKEN is required", file=sys.stderr)
        return 1
    try:
        receipt = resolve_image(
            RegistryClient(token, args.timeout), args.image, args.source_commit
        )
        Path(args.output_file).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except ImageResolutionError as exc:
        print(f"image resolution failed: {exc}", file=sys.stderr)
        return 1
    print(f"resolved existing artifact: {receipt['image_ref']}, revision={args.source_commit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
