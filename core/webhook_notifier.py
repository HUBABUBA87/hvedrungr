"""
core.webhook_notifier
---------------------
Sending alerts to external messengers.

Two payload formats are supported:
  * Slack Incoming Webhooks — uses the `text` field and nested blocks;
  * Microsoft Teams (Office 365 Connector / Power Automate) — uses a
    simplified JSON with a `text` field.

If webhook_url is not set, messages are only printed to the console.
This allows testing the system locally without any dependencies on
third-party services.
"""

import json
from typing import Optional

try:
    import requests
except ImportError:  # package is optional for running in "console-only" mode
    requests = None  # type: ignore

from core import logger


def _format_slack(event: dict) -> dict:
    mitre = event.get("mitre", {})
    text = (
        f":rotating_light: *Hveðrungr alert*\n"
        f"• Source: `{event.get('src_ip', '-')}`\n"
        f"• Module: `{event.get('module', '-')}`\n"
        f"• Event: `{event.get('event_type', '-')}`\n"
        f"• MITRE: *{mitre.get('tactic', '-')}* "
        f"(`{mitre.get('technique_id', '-')}`) — "
        f"{mitre.get('description', '-')}\n"
        f"• Time: {event.get('timestamp', '-')}"
    )
    info = event.get("info") or event.get("command")
    if info:
        text += f"\n• Detail: ```{info}```"
    return {"text": text}


def _format_teams(event: dict) -> dict:
    mitre = event.get("mitre", {})
    info = event.get("info") or event.get("command") or ""
    return {
        "text": (
            f"**Hveðrungr alert**\n\n"
            f"- Source: `{event.get('src_ip', '-')}`\n"
            f"- Module: `{event.get('module', '-')}`\n"
            f"- Event: `{event.get('event_type', '-')}`\n"
            f"- MITRE: **{mitre.get('tactic', '-')}** "
            f"(`{mitre.get('technique_id', '-')}`) — "
            f"{mitre.get('description', '-')}\n"
            f"- Time: {event.get('timestamp', '-')}\n"
            f"- Detail: `{info}`"
        )
    }


def send_alert(event: dict, webhook_url: Optional[str], webhook_type: str = "slack") -> bool:
    """
    Sends an alert to the messenger. Returns True if delivery is successful.
    In case of an error (no network, incorrect URL), it logs a warning
    but does not crash — the trap must operate under any conditions.
    """
    log = logger.get_logger("webhook")

    if not webhook_url or webhook_type == "none":
        # Demo mode without an external service — print to console.
        print("[ALERT]", json.dumps(event, ensure_ascii=False))
        return True

    if requests is None:
        log.warning("The requests library is not installed; the alert was not sent.")
        return False

    if webhook_type == "teams":
        payload = _format_teams(event)
    else:
        payload = _format_slack(event)

    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        if 200 <= r.status_code < 300:
            return True
        log.warning("Webhook responded with code %s: %s", r.status_code, r.text[:200])
    except Exception as e:  # pragma: no cover
        log.warning("Webhook dispatch failure: %s", e)
    return False
