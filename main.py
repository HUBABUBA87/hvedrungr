"""
main
----
Hveðrungr system entry point.

Launches three key modules in parallel threads:
  * Narfa fjöturr (SSH-tarpit)
  * Lokanet      (fake shell with honeytokens)
  * Lokasenna    works event-driven — alerts come from both other modules.

Usage:
    python main.py                # with config.yaml in the current directory
    python main.py path/to/config.yaml

To stop — press Ctrl+C.
"""

import signal
import sys
import threading
import time

try:
    import yaml
except ImportError:
    print("ERROR: install PyYAML — pip install pyyaml")
    sys.exit(1)

from core import logger
from narfa.tarpit import NarfaTarpit
from lokanet.shell_server import LokanetShell


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> int:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = load_config(cfg_path)

    logger.init_logger(
        log_dir=cfg["logging"]["log_dir"],
        json_log=cfg["logging"]["json_log"],
        text_log=cfg["logging"]["text_log"],
        level=cfg["logging"].get("level", "INFO"),
    )

    log = logger.get_logger("main")
    log.info("Starting Hveðrungr…")

    bind_host = cfg.get("bind_host", "0.0.0.0")
    webhook_url = (cfg.get("lokasenna") or {}).get("webhook_url") or None
    webhook_type = (cfg.get("lokasenna") or {}).get("webhook_type", "slack")

    running = []

    if cfg.get("narfa", {}).get("enabled"):
        narfa_cfg = cfg["narfa"]
        narfa = NarfaTarpit(
            host=bind_host,
            port=narfa_cfg["port"],
            banner=narfa_cfg["banner"],
            byte_delay=float(narfa_cfg.get("byte_delay_seconds", 1.0)),
            hold_seconds=float(narfa_cfg.get("hold_seconds", 60)),
            webhook_url=webhook_url,
            webhook_type=webhook_type,
        )
        t = threading.Thread(target=narfa.start, daemon=True)
        t.start()
        running.append(("narfa", narfa, t))

    if cfg.get("lokanet", {}).get("enabled"):
        lkn_cfg = cfg["lokanet"]
        lokanet = LokanetShell(
            host=bind_host,
            port=lkn_cfg["port"],
            hostname=lkn_cfg.get("hostname", "srv-01"),
            username=lkn_cfg.get("username", "admin"),
            webhook_url=webhook_url,
            webhook_type=webhook_type,
        )
        t = threading.Thread(target=lokanet.start, daemon=True)
        t.start()
        running.append(("lokanet", lokanet, t))

    log.info("All modules started (%d). Press Ctrl+C to stop.", len(running))

    stop_event = threading.Event()

    def _sig(_sig, _frm):
        log.info("Shutdown signal received.")
        stop_event.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        for name, mod, _ in running:
            try:
                mod.stop()
            except Exception as e:  # pragma: no cover
                log.warning("Error while stopping %s: %s", name, e)
        log.info("Hveðrungr stopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
