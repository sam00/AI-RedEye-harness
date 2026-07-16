"""Webhook notifier (Slack / Teams / Discord / generic).

Posts a compact summary of the scan to a webhook URL. Optional HMAC-SHA256
signature in the ``X-Redteam-Signature`` header lets receivers verify the
sender (the secret comes from ``REDEYE_WEBHOOK_SECRET``).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)


def _validate_url(url: str) -> bool:
    """SSRF guard: refuse webhook URLs that point at loopback or link-local /
    cloud-metadata addresses (127.0.0.0/8, ::1, localhost, 169.254.0.0/16
    including 169.254.169.254). A poisoned ``REDEYE_WEBHOOK_URL`` must not let
    the notifier probe internal services from CI.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        log.error("webhook url is not parseable; refusing to post")
        return False
    if parsed.scheme not in ("http", "https"):
        log.error("webhook url scheme %r not allowed (http/https only)", parsed.scheme)
        return False
    host = parsed.hostname
    if not host:
        log.error("webhook url has no host; refusing to post")
        return False
    if host.lower() == "localhost":
        log.error("webhook url targets localhost; refusing to post")
        return False
    try:
        addrs = [ipaddress.ip_address(host)]
    except ValueError:
        # Hostname, not an IP literal: resolve best-effort. If resolution
        # fails, fall through -- the literal host was already vetted above.
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
        except (OSError, ValueError):
            addrs = []
    for addr in addrs:
        addr = getattr(addr, "ipv4_mapped", None) or addr
        if addr.is_loopback or addr.is_link_local:
            log.error("webhook url resolves to blocked address %s; refusing to post", addr)
            return False
    return True


def _compose_payload(
    *,
    kind: str,
    target: str,
    application_id: str | None,
    manifest,  # type: ignore[no-untyped-def]
) -> dict[str, Any]:
    summary = (
        f"RedEye scan complete: {target}"
        + (f" (AppId {application_id})" if application_id else "")
        + f" -- findings={manifest.finding_count}"
        f" dropped={manifest.dropped_count}"
        f" cost=${manifest.total_cost_usd:.3f}"
    )
    if kind == "slack":
        return {
            "text": summary,
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*RedEye*\n{summary}"}},
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"profile: `{manifest.profile}`"},
                        {
                            "type": "mrkdwn",
                            "text": f"target SHA: `{manifest.target_sha or 'unknown'}`",
                        },
                    ],
                },
            ],
        }
    if kind == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "FF6F00" if manifest.finding_count else "2EB67D",
            "summary": "RedEye scan",
            "title": "RedEye scan complete",
            "text": summary,
            "sections": [
                {
                    "facts": [
                        {"name": "Target", "value": target},
                        {"name": "App ID", "value": application_id or "-"},
                        {"name": "Profile", "value": manifest.profile},
                        {"name": "Target SHA", "value": manifest.target_sha or "unknown"},
                        {"name": "Findings", "value": str(manifest.finding_count)},
                        {"name": "Dropped", "value": str(manifest.dropped_count)},
                        {"name": "Cost (USD)", "value": f"${manifest.total_cost_usd:.3f}"},
                    ]
                }
            ],
        }
    if kind == "discord":
        return {"content": summary}
    # generic
    return {
        "tool": "redeye",
        "version": manifest.version,
        "target": target,
        "application_id": application_id,
        "profile": manifest.profile,
        "target_sha": manifest.target_sha,
        "findings": manifest.finding_count,
        "dropped": manifest.dropped_count,
        "total_cost_usd": manifest.total_cost_usd,
        "summary": summary,
    }


def post_summary(
    *,
    url: str,
    kind: str,
    target: str,
    application_id: str | None,
    manifest,  # type: ignore[no-untyped-def]
    timeout: float = 10.0,
) -> bool:
    if not _validate_url(url):
        return False
    payload = _compose_payload(
        kind=kind, target=target, application_id=application_id, manifest=manifest
    )
    body = json.dumps(payload).encode("utf-8")
    headers = {"content-type": "application/json"}
    secret = os.environ.get("REDEYE_WEBHOOK_SECRET")
    if secret:
        sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["x-redteam-signature"] = f"sha256={sig}"

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, content=body, headers=headers)
        if 200 <= resp.status_code < 300:
            return True
        log.warning("webhook returned %d: %s", resp.status_code, resp.text[:200])
        return False
    except httpx.HTTPError as exc:
        log.warning("webhook post failed: %s", exc)
        return False
