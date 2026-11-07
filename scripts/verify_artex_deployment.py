#!/usr/bin/env python3
"""Poll ARTEX health until the deployed full source revision matches."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class DeploymentVerificationError(RuntimeError):
    pass


def validate_base_url(base_url: str) -> str:
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
    return base_url.rstrip("/")


def read_health(base_url: str, timeout: float) -> dict[str, Any]:
    url = validate_base_url(base_url) + "/api/health"
    request = Request(url, headers={"User-Agent": "curl/8.4.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise DeploymentVerificationError(f"/api/health returned HTTP {response.status}")
            payload = response.read()
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
) -> None:
    root = validate_base_url(base_url)
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
            health = read_health(root, min(request_timeout, max(remaining, 0.1)))
        except (
            DeploymentVerificationError,
            URLError,
            TimeoutError,
            socket.timeout,
            ConnectionError,
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
    args = parser.parse_args()
    try:
        verify_deployment(
            args.base_url,
            args.expected_commit,
            args.timeout,
            args.interval,
            args.request_timeout,
        )
    except DeploymentVerificationError as exc:
        print(f"deployment verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
