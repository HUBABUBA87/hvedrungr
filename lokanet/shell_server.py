"""
lokanet.shell_server
--------------------
Implementation of the "Lokanet" concept — a network of illusion tokens and a fake
file system.

The server simulates a simple telnet-shell. It accepts connections,
prompts for a login and password, and then lets the user "inside" — into a pre-configured
fake Linux environment. Any entered command is logged,
mapped to MITRE ATT&CK, and if it is a sensitive operation
(reading /etc/passwd, outputting .bash_history, attempting to use
a token from a file), an alert is sent.

This is intentionally a medium-interaction trap: it provides a sufficiently realistic
environment for a scanner or human to "immerse" themselves in research, but does not
have a real kernel through which the trap could be used as a
stepping stone for an attack on the real network.
"""

import socket
import threading
import time
from typing import Optional

from core import logger, mitre_mapper, webhook_notifier
from lokanet import fake_fs

# Basic set of commands to which the shell gives a meaningful response.
# All other commands cause "command not found" — this is both realistic
# and annoying for the attacker (wasting their effort).
SUPPORTED = ("ls", "cat", "cd", "pwd", "whoami", "id", "uname",
             "hostname", "ifconfig", "ip", "netstat", "ps",
             "history", "wget", "curl", "echo", "find",
             "exit", "logout", "quit")


class LokanetShell:
    def __init__(self, host: str, port: int, hostname: str, username: str,
                 webhook_url: Optional[str], webhook_type: str):
        self.host = host
        self.port = port
        self.hostname = hostname
        self.username = username
        self.webhook_url = webhook_url
        self.webhook_type = webhook_type
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(128)
        log = logger.get_logger("lokanet")
        log.info("Lokanet shell listening on %s:%s", self.host, self.port)
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

    # ---------- low-level I/O ----------

    def _send(self, c: socket.socket, text: str) -> None:
        try:
            c.sendall(text.encode("utf-8", errors="replace"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            raise

    def _recv_line(self, c: socket.socket, timeout: float = 60.0) -> Optional[str]:
        c.settimeout(timeout)
        buf = b""
        while not self._stop.is_set():
            try:
                ch = c.recv(1)
            except (socket.timeout, ConnectionResetError, OSError):
                return None
            if not ch:
                return None
            if ch in (b"\r", b"\n"):
               # Consume both CR LF
                try:
                    c.settimeout(0.1)
                    extra = c.recv(1)
                    if extra and extra not in (b"\r", b"\n"):
                        buf += extra
                except (socket.timeout, OSError):
                    pass
                return buf.decode("utf-8", errors="replace")
            buf += ch
            # Prevent infinite reading
            if len(buf) > 4096:
                return buf.decode("utf-8", errors="replace")

    # ---------- main session ----------

    def _handle(self, client: socket.socket, addr) -> None:
        src_ip, src_port = addr
        log = logger.get_logger("lokanet")
        log.info("Lokanet: connection from %s:%s", src_ip, src_port)

        # Log the connection itself
        match = mitre_mapper.map_event("__tcp_connect__")
        event = logger.log_event(
            module="lokanet",
            event_type="connection",
            payload={"src_ip": src_ip, "src_port": src_port,
                     "info": "telnet connect",
                     "mitre": match.as_dict()},
        )
        webhook_notifier.send_alert(event, self.webhook_url, self.webhook_type)

        try:
            self._send(client, f"\r\nUbuntu 22.04.3 LTS\r\n{self.hostname} login: ")
            user = self._recv_line(client, timeout=30) or ""
            self._send(client, "Password: ")
            pwd = self._recv_line(client, timeout=30) or ""

            # Register the authorization attempt — this is the Credential Access stage
            auth_match = mitre_mapper.map_event("__auth_attempt__")
            auth_event = logger.log_event(
                module="lokanet",
                event_type="auth_attempt",
                payload={"src_ip": src_ip,
                         "info": f"login='{user[:32]}' password='{pwd[:32]}'",
                         "username": user[:64], "password": pwd[:64],
                         "mitre": auth_match.as_dict()},
            )
            webhook_notifier.send_alert(auth_event, self.webhook_url,
                                        self.webhook_type)

            # The trap always lets users in — this is the decoy itself.
            self._send(client,
                       "\r\nWelcome to Ubuntu 22.04.3 LTS\r\n"
                       "Last login: Mon Nov 13 18:42:11 2026 from 10.20.30.40\r\n")
            self._shell_loop(client, src_ip, user or "admin")

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
            logger.log_event(
                module="lokanet",
                event_type="session_end",
                payload={"src_ip": src_ip, "info": "shell closed",
                         "mitre": mitre_mapper.map_event("__tcp_connect__").as_dict()},
            )

    def _shell_loop(self, c: socket.socket, src_ip: str, user: str) -> None:
        cwd = f"/home/{user}" if fake_fs.is_dir(f"/home/{user}") else "/root"
        while not self._stop.is_set():
            prompt = f"\r\n{user}@{self.hostname}:{cwd}$ "
            self._send(c, prompt)
            cmd = self._recv_line(c, timeout=300)
            if cmd is None:
                return
            cmd = cmd.strip()
            if not cmd:
                continue

            # MITRE mapping
            match = mitre_mapper.map_event(cmd)

            # Check if the command contains a honeytoken
            token_name = fake_fs.contains_honeytoken(cmd)
            ev_type = "command"
            if token_name:
                ev_type = "honeytoken_used"
                match = mitre_mapper.map_event("__honeytoken__")

            event = logger.log_event(
                module="lokanet",
                event_type=ev_type,
                payload={"src_ip": src_ip,
                         "info": cmd[:512],
                         "command": cmd[:512],
                         "honeytoken": token_name,
                         "cwd": cwd,
                         "mitre": match.as_dict()},
            )
            webhook_notifier.send_alert(event, self.webhook_url,
                                        self.webhook_type)

            # Command processing
            cwd = self._dispatch(c, cmd, cwd, user)
            if cwd is None:  # exit
                return

    # ---------- command dispatcher ----------

    def _dispatch(self, c: socket.socket, cmd: str, cwd: str, user: str):
        parts = cmd.split()
        head = parts[0] if parts else ""

        if head in ("exit", "logout", "quit"):
            self._send(c, "\r\nlogout\r\n")
            return None

        if head == "pwd":
            self._send(c, f"\r\n{cwd}")

        elif head == "whoami":
            self._send(c, f"\r\n{user}")

        elif head == "id":
            self._send(c, f"\r\nuid=1000({user}) gid=1000({user}) "
                          f"groups=1000({user}),27(sudo)")

        elif head == "uname":
            self._send(c, "\r\nLinux srv-fin-01 5.15.0-91-generic "
                          "#101-Ubuntu SMP x86_64 GNU/Linux")

        elif head == "hostname":
            self._send(c, f"\r\n{self.hostname}")

        elif head == "ifconfig" or (head == "ip" and len(parts) > 1):
            self._send(c, "\r\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>\r\n"
                          "        inet 10.20.30.55  netmask 255.255.255.0\r\n"
                          "        ether 52:54:00:8a:9c:1d  txqueuelen 1000")

        elif head == "ls":
            target = parts[1] if len(parts) > 1 else cwd
            target = self._resolve(target, cwd)
            if fake_fs.is_dir(target):
                items = fake_fs.list_dir(target)
                self._send(c, "\r\n" + "  ".join(items))
            elif fake_fs.file_exists(target):
                self._send(c, f"\r\n{target.split('/')[-1]}")
            else:
                self._send(c, f"\r\nls: cannot access '{target}': "
                              f"No such file or directory")

        elif head == "cd":
            target = parts[1] if len(parts) > 1 else f"/home/{user}"
            new = self._resolve(target, cwd)
            if fake_fs.is_dir(new):
                cwd = new
            else:
                self._send(c, f"\r\n-bash: cd: {target}: No such file or directory")

        elif head == "cat":
            if len(parts) < 2:
                self._send(c, "\r\ncat: missing operand")
            else:
                target = self._resolve(parts[1], cwd)
                if fake_fs.file_exists(target):
                    self._send(c, "\r\n" + fake_fs.read_file(target).rstrip("\n"))
                else:
                    self._send(c, f"\r\ncat: {parts[1]}: No such file or directory")

        elif head == "history":
            target = f"/home/{user}/.bash_history"
            if fake_fs.file_exists(target):
                lines = fake_fs.read_file(target).splitlines()
                out = "\r\n".join(f"{i+1:5d}  {ln}" for i, ln in enumerate(lines))
                self._send(c, "\r\n" + out)
            else:
                self._send(c, "")

        elif head == "ps":
            self._send(c, "\r\n  PID TTY          TIME CMD\r\n"
                          "  982 pts/0    00:00:00 bash\r\n"
                          " 1102 pts/0    00:00:00 ps")

        elif head == "netstat":
            self._send(c,
                "\r\nActive Internet connections\r\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address  State\r\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*        LISTEN\r\n"
                "tcp        0      0 10.20.30.55:5432        0.0.0.0:*        LISTEN")

        elif head == "echo":
            self._send(c, "\r\n" + " ".join(parts[1:]))

        elif head == "find":
            self._send(c, "\r\n" + "\r\n".join(sorted(fake_fs.FS.keys())))

        elif head in ("wget", "curl"):
            # Simulate slow download to toy with the attacker a bit more
            self._send(c, "\r\nconnecting...")
            time.sleep(2)
            self._send(c, " ok\r\n100% downloaded")

        else:
            self._send(c, f"\r\n-bash: {head}: command not found")

        return cwd

    @staticmethod
    def _resolve(path: str, cwd: str) -> str:
        if path.startswith("/"):
            new = path
        elif path == "..":
            new = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
        elif path == ".":
            new = cwd
        else:
            new = f"{cwd.rstrip('/')}/{path}"
        # Normalize multiple slashes
        while "//" in new:
            new = new.replace("//", "/")
        return new.rstrip("/") or "/"
