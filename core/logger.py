"""
core.logger
-----------
Single logging point for the Hveðrungr system.

All components (Narfa fjöturr, Lokanet, Lokasenna) write events into two
parallel files:
  * events.jsonl — structured JSON-Lines for further analysis;
  * hvedrungr.log — standard text log for the operator.

A separate JSON format is required so that logs can be loaded without extra
processing into SIEM class systems (Splunk, ELK, Wazuh).
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
_json_path = None
_text_logger = None


def init_logger(log_dir: str, json_log: str, text_log: str, level: str = "INFO") -> None:
    """Creates the log directory and configures the text logger."""
    global _json_path, _text_logger

    os.makedirs(log_dir, exist_ok=True)
    _json_path = os.path.join(log_dir, json_log)

    _text_logger = logging.getLogger("hvedrungr")
    _text_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    _text_logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(os.path.join(log_dir, text_log), encoding="utf-8")
    fh.setFormatter(fmt)
    _text_logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    _text_logger.addHandler(ch)


def log_event(module: str, event_type: str, payload: dict) -> dict:
    """
    Writes the event to the JSONL file and duplicates a short string in the text log.
    Returns the formed event object — it can be immediately passed to the Lokasenna
    module for alerting.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "module": module,
        "event_type": event_type,
        **payload,
    }
    with _lock:
        if _json_path:
            with open(_json_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
    if _text_logger:
        src = payload.get("src_ip", "-")
        info = payload.get("info") or payload.get("command") or ""
        _text_logger.info("[%s] %s | src=%s | %s", module, event_type, src, info)
    return event


def get_logger(name: str) -> logging.Logger:
    """Helper getter: returns a child-logger for a specific module."""
    return logging.getLogger(f"hvedrungr.{name}")
