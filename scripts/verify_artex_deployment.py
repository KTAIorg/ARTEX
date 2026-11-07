#!/usr/bin/env python3
"""Poll ARTEX health over pinned TLS until the full source revision matches."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class DeploymentVerificationError(RuntimeError):
    pass


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise DeploymentVerificationError(f"/api/health redirect refused: HTTP {code}")


def validate_base_url(base_url: str, allow_http_loopback: bool = False) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise DeploymentVerificationError(
            "base URL must be an HTTP(S) origin without userinfo, path, query or fragment"
        )
    if parsed.scheme == "http":
        if not allow_http_loopback:
            raise DeploymentVerificationError("production health checks require HTTPS")
        try:
            host = parsed.hostname
            if host is None or not ipaddress.ip_address(host).is_loopback:
                raise DeploymentVerificationError(
                    "HTTP health checks are allowed only for explicit loopback smoke tests"
                )
        except ValueError as exc:
            raise DeploymentVerificationError("HTTP health check host must be a loopback IP") from exc
    return base_url.rstrip("/")


def read_health(
    base_url: str,
    timeout: float,
    ca_file: str | None = None,
    allow_http_loopback: bool = False,
) -> dict[str, Any]:
    url = validate_base_url(base_url, allow_http_loopback) + "/api/health"
    handlers: list[Any] = [RejectRedirects()]
    if url.startswith("https://"):
        if not ca_file:
            raise DeploymentVerificationError("--ca-file is required for HTTPS health checks")
        try:
            context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise DeploymentVerificationError(f"could not load health CA: {exc}") from exc
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        handlers.append(HTTPSHandler(context=context))
    opener = build_opener(*handlers)
    request = Request(url, headers={"User-Agent": "artex-deployment-verifier/1.0"})
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise DeploymentVerificationError(f"/api/health returned HTTP {response.status}")
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise DeploymentVerificationError("/api/health response is too large")
    except HTTPError as exc:
        raise DeploymentVerificationError(f"/api/health returned HTTP {exc.code}") from exc
    try:
        document: Any = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentVerificationError("/api/health did not return valid JSON") from exc
    if not isinstance(document, dict):
        raise DeploymentVerificationError("/api/health did not return an object")
    if document.get("ok") is not True or document.get("service") != "artex":
        raise DeploymentVerificationError("/api/health is not healthy ARTEX")
    version = document.get("version")
    if not isinstance(version, str) or not version:
        raise DeploymentVerificationError("/api/health did not contain a version")
    return document


def verify_deployment(
    base_url: str,
    expected_commit: str,
    timeout: float,
    interval: float,
    request_timeout: float = 10.0,
    ca_file: str | None = None,
    allow_http_loopback: bool = False,
) -> None:
    root = validate_base_url(base_url, allow_http_loopback)
    if root.startswith("https://") and not ca_file:
        raise DeploymentVerificationError("--ca-file is required for HTTPS health checks")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise DeploymentVerificationError("expected commit must be a full lowercase hexadecimal SHA")
    deadline = time.monotonic() + timeout
    last_status = "no response received"

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeploymentVerificationError(
                f"deployment did not reach {expected_commit} before timeout; {last_status}"
            )
        try:
            health = read_health(
                root,
                min(request_timeout, max(remaining, 0.1)),
                ca_file,
                allow_http_loopback,
            )
        except (
            DeploymentVerificationError,
            URLError,
            TimeoutError,
            socket.timeout,
            ConnectionError,
            ssl.SSLError,
        ) as exc:
            last_status = f"last health failure: {exc}"
        else:
            observed = health["version"].lower()
            if observed == expected_commit:
                print(f"deployment verified: /api/health is healthy, version={observed}")
                return
            last_status = f"last observed version={observed}"
            print(f"waiting for version={expected_commit}; {last_status}", flush=True)
        time.sleep(min(interval, max(deadline - time.monotonic(), 0)))


def _non_negative(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--timeout", type=_non_negative, default=300.0)
    parser.add_argument("--interval", type=_non_negative, default=5.0)
    parser.add_argument("--request-timeout", type=_non_negative, default=10.0)
    parser.add_argument("--ca-file")
    parser.add_argument("--allow-http-loopback", action="store_true")
    args = parser.parse_args()
    try:
        verify_deployment(
            args.base_url,
            args.expected_commit,
            args.timeout,
            args.interval,
            args.request_timeout,
            args.ca_file,
            args.allow_http_loopback,
        )
    except DeploymentVerificationError as exc:
        print(f"deployment verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
