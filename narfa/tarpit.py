"""
narfa.tarpit
------------
Implementation of the "Narfa fjöturr" concept — a connection delay module
(tarpitting) for an SSH-like service.

Operating principle:
  1. The server listens on a TCP port (default 2222).
  2. When a scanner connects, it sends the SSH banner one byte at a time
     with a configurable delay (e.g., 1 byte/sec).
  3. Most scanners and botnets set a connection timeout of 10–30 seconds.
     During this time, the full banner fails to arrive, meaning the scanner
     cannot proceed to the handshake phase and is forced to drop the connection
     (or wait long, wasting its resources).
  4. After sending the banner, the server keeps the connection in a "hanging"
     state for some time, reading data byte-by-byte with a high delay.

This module does not implement a real SSH protocol. Its purpose is to create
a highly cost-effective yet convincing sensor that logs both the existence
and the lifetime of each connection.
"""

import socket
import threading
import time
from typing import Optional

from core import logger, mitre_mapper, webhook_notifier


class NarfaTarpit:
    def __init__(self, host: str, port: int, banner: str,
                 byte_delay: float, hold_seconds: float,
                 webhook_url: Optional[str], webhook_type: str):
        self.host = host
        self.port = port
        self.banner = banner.rstrip("\r\n") + "\r\n"
        self.byte_delay = byte_delay
        self.hold_seconds = hold_seconds
        self.webhook_url = webhook_url
        self.webhook_type = webhook_type
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(128)
        log = logger.get_logger("narfa")
        log.info("Narfa fjöturr listening on %s:%s (delay %.2fs/byte)",
                 self.host, self.port, self.byte_delay)
        try:
            while not self._stop.is_set():
                try:
                    client, addr = self._sock.accept()
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(client, addr),
                                 daemon=True).start()
        finally:
            if self._sock:
                self._sock.close()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

    def _handle(self, client: socket.socket, addr) -> None:
        src_ip, src_port = addr
        t_start = time.time()
        log = logger.get_logger("narfa")
        log.info("Connection from %s:%s — entering tarpit", src_ip, src_port)

        # 1. Log the connection event.
        match = mitre_mapper.map_event("__tcp_connect__")
        event = logger.log_event(
            module="narfa",
            event_type="connection",
            payload={
                "src_ip": src_ip,
                "src_port": src_port,
                "info": "TCP connect — entering tarpit",
                "mitre": match.as_dict(),
            },
        )
        webhook_notifier.send_alert(event, self.webhook_url, self.webhook_type)

        # 2. Slowly send the banner byte by byte.
        try:
            client.settimeout(self.byte_delay * 5 + 5)
            for ch in self.banner.encode("utf-8"):
                if self._stop.is_set():
                    break
                try:
                    client.sendall(bytes([ch]))
                except (BrokenPipeError, ConnectionResetError):
                    log.info("Client %s disconnected during banner", src_ip)
                    self._finalize(src_ip, t_start, "abort_during_banner")
                    return
                time.sleep(self.byte_delay)

            # 3. Hold the connection for another `hold_seconds`, slowly consuming data.
            client.settimeout(self.hold_seconds)
            held = 0.0
            while held < self.hold_seconds and not self._stop.is_set():
                try:
                    data = client.recv(1)
                    if not data:
                        break
                    # Intentional pause before receiving the next byte
                    time.sleep(self.byte_delay)
                    held += self.byte_delay
                except socket.timeout:
                    break
                except (ConnectionResetError, OSError):
                    break
        finally:
            try:
                client.close()
            except OSError:
                pass
            self._finalize(src_ip, t_start, "session_closed")

    def _finalize(self, src_ip: str, t_start: float, reason: str) -> None:
        duration = round(time.time() - t_start, 2)
        match = mitre_mapper.map_event("__tcp_connect__")
        event = logger.log_event(
            module="narfa",
            event_type="session_end",
            payload={
                "src_ip": src_ip,
                "info": f"{reason}; held={duration}s",
                "duration_sec": duration,
                "mitre": match.as_dict(),
            },
        )
        # Do not duplicate a separate alert in the webhook — this is a final event
