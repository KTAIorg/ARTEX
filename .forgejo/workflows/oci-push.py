#!/usr/bin/env python3
"""Push an OCI layout tar or docker-save tar in chunks under a proxy body limit."""

import argparse
import hashlib
import json
import os
import sys
import tarfile
import urllib.error
import urllib.request

CHUNK = 32 * 1024 * 1024
# Cloudflare 对 Python-urllib 默认 UA 返回 403，请求到不了 Zot。用容器客户端的 UA。
USER_AGENT = "docker/28.0.4"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"


class Registry:
    def __init__(self, base, repository, token):
        self.base = base.rstrip("/")
        self.repository = repository.strip("/")
        self.token = token

    def _request(self, method, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Authorization", "Bearer " + self.token)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read(400).decode("utf-8", "replace")
            raise SystemExit(f"{method} {exc.code} {url.split('?', 1)[0]} {body}") from exc

    def head_blob(self, digest):
        url = f"{self.base}/v2/{self.repository}/blobs/{digest}"
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as exc:
            body = exc.read(200).decode("utf-8", "replace")
            exc.close()
            if exc.code == 404:
                return False
            raise SystemExit(f"HEAD {exc.code} {url} {body}") from exc

    def upload(self, digest, blob):
        if self.head_blob(digest):
            return
        start = f"{self.base}/v2/{self.repository}/blobs/uploads/"
        status, headers, _ = self._request("POST", start, data=b"")
        if status not in (202, 201):
            raise SystemExit(f"upload start {status}")
        loc = location_of(headers, self.base)
        size = len(blob)
        if size <= CHUNK:
            self._request(
                "PUT",
                with_digest(loc, digest),
                data=blob,
                headers={"Content-Type": "application/octet-stream"},
            )
            return
        # 数据全部用 PATCH 追加。结束用空 PUT 只提交 digest。
        # 把最后一块放进 PUT 时，Zot 会把这段当成整包校验并返回 416。
        offset = 0
        while offset < size:
            end = min(offset + CHUNK, size)
            _, headers, _ = self._request(
                "PATCH",
                loc,
                data=blob[offset:end],
                headers={"Content-Type": "application/octet-stream"},
            )
            try:
                loc = location_of(headers, self.base)
            except SystemExit:
                pass
            offset = end
        self._request(
            "PUT",
            with_digest(loc, digest),
            data=b"",
            headers={"Content-Type": "application/octet-stream"},
        )

    def put_manifest(self, tag, media_type, body):
        url = f"{self.base}/v2/{self.repository}/manifests/{tag}"
        self._request("PUT", url, data=body, headers={"Content-Type": media_type})


def location_of(headers, base):
    loc = ""
    for key, value in headers.items():
        if key.lower() == "location":
            loc = value.strip()
    if loc.startswith("http://") or loc.startswith("https://"):
        return loc
    if loc.startswith("/"):
        return base + loc
    raise SystemExit("upload Location missing")


def with_digest(loc, digest):
    sep = "&" if "?" in loc else "?"
    return f"{loc}{sep}digest={digest}"


def sha256_bytes(blob):
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def members(archive):
    found = {}
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            found[member.name.lstrip("./")] = extracted.read()
    return found


def descriptors_from_oci(files):
    index = json.loads(files["index.json"])
    blobs = {}
    for name, blob in files.items():
        if name.startswith("blobs/sha256/"):
            blobs["sha256:" + name.rsplit("/", 1)[-1]] = blob
    root = index["manifests"][0]
    return root["digest"], root.get("mediaType", ""), blobs


def descriptors_from_docker(files):
    manifests = json.loads(files["manifest.json"])
    item = manifests[0]
    config = files[item["Config"]]
    config_digest = sha256_bytes(config)
    layers = []
    blobs = {config_digest: config}
    for layer_name in item["Layers"]:
        layer = files[layer_name]
        digest = sha256_bytes(layer)
        blobs[digest] = layer
        layers.append(
            {"mediaType": DOCKER_LAYER, "digest": digest, "size": len(layer)}
        )
    manifest = {
        "schemaVersion": 2,
        "mediaType": DOCKER_MANIFEST,
        "config": {
            "mediaType": DOCKER_CONFIG,
            "digest": config_digest,
            "size": len(config),
        },
        "layers": layers,
    }
    body = json.dumps(manifest, separators=(",", ":")).encode()
    digest = sha256_bytes(body)
    blobs[digest] = body
    return digest, DOCKER_MANIFEST, blobs


def push_archive(archive, registry, repository, tags, token, kind):
    files = members(archive)
    if kind == "auto":
        kind = "oci" if "index.json" in files else "docker"
    if kind == "oci":
        digest, media_type, blobs = descriptors_from_oci(files)
    else:
        digest, media_type, blobs = descriptors_from_docker(files)
    if not media_type:
        media_type = "application/vnd.oci.image.manifest.v1+json"
    client = Registry(registry, repository, token)
    for blob_digest, blob in blobs.items():
        client.upload(blob_digest, blob)
    manifest = blobs[digest]
    for tag in tags:
        client.put_manifest(tag, media_type, manifest)
    return digest


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", action="append", required=True)
    parser.add_argument("--kind", choices=("auto", "oci", "docker"), default="auto")
    args = parser.parse_args(argv)
    token = os.environ.get("OCI_BEARER", "")
    if not token:
        raise SystemExit("OCI_BEARER is empty")
    digest = push_archive(
        args.archive, args.registry, args.repository, args.tag, token, args.kind
    )
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
