# Architecture of the Hveðrungr System

This document describes the internal structure of the prototype: components, data flows, interaction protocols, MITRE ATT&CK integration, and the deployment model. It is used as the technical foundation for the research article currently being prepared.

## 1. Overview

The prototype is built as a set of independent service threads sharing a common core. Architecturally, it represents a classic **three-tier structure**: the event capture layer (sensors), the normalization and logging layer (core), and the alerting and analytics layer (alerting).
```text
            ┌──────────── EXTERNAL NETWORK / Internet ────────────┐
            │                                                     │
            │    nmap, hydra, botnets, manual connections         │
            │                                                     │
            ▼                                                     ▼
   ┌──────────────────────┐                 ┌────────────────────────┐
   │ Narfa fjöturr        │                 │ Lokanet                │
   │ (SSH tarpit :2222)   │                 │ (fake shell :2323)     │
   │ • slow banner        │                 │ • login / password     │
   │   delivery 1 b/s     │                 │ • commands ls/cat/...  │
   │ • session holding    │                 │ • fake /etc/passwd     │
   │                      │                 │ • honeytokens          │
   └──────────┬───────────┘                 └────────────┬───────────┘
              │ events                                   │ events
              ▼                                          ▼
        ┌──────────────────────────────────────────────────┐
        │                    core / logger                 │
        │ • JSON-Lines in logs/events.jsonl                │
        │ • text log in logs/hvedrungr.log                 │
        │ • thread-safe writing                            │
        └────────────────────┬─────────────────────────────┘
                             │
                             ▼
                    ┌──────────────────────┐
                    │ core / mitre_mapper  │
                    │ (signature → TTP)    │
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┴──────────────────┐
        ▼                                         ▼
┌─────────────────┐                 ┌──────────────────────────┐
│ Real-time alert │                 │ Lokasenna / analyzer     │
│ (Slack / Teams) │                 │ (post-analytics from JSONl)
│ via webhook     │                 │                          │
└─────────────────┘                 └──────────────────────────┘
```
## 2. Component Description

### 2.1. Narfa fjöturr — Tarpitting Module

Task: Create a "sticky trap" for automated scanners. Implemented as a simple TCP socket server.

Connection processing sequence:
1. `accept()` of a new connection, logging the `connection` event (MITRE `T1595.001 — Active Scanning`).
2. In a loop over the banner bytes: `send` one byte → `sleep(byte_delay)`.
3. If the peer has not closed yet — `recv(1)` with an additional delay of `hold_seconds`, keeping the socket open.
4. In `finally` — logging the final `session_end` event with duration.

Why it works:
* Most scanners and botnets set a general connection timeout of 10–30 seconds. With a delay of 1 byte/sec and a banner length of 40 bytes, the scanner will not wait for the end of the banner and is forced to drop the connection.
* Each such unclosed "hang" is a wasted scanner thread. The attacker's side has a limited number of concurrent connections, so the trap effectively slows down the entire campaign.

### 2.2. Lokanet — Fake Shell with Honeytokens

Task: Create a plausible environment where the attacker spends more time than needed for their identification.

Also implemented on sockets. The supported interface is telnet-like (direct text exchange without encryption). For a trap, this is not a flaw, but an advantage: we do not have a real OS, so realistic SSH emulation is not required here.

Session processing logic:
1. Login prompt, password prompt → logging the `auth_attempt` event (MITRE `T1110 — Brute Force`). The trap always lets the user in.
2. Shell loop: wait for a command up to `\n` → parse → execute via the dispatcher (`_dispatch` method).
3. Each executed command:
   * normalized to lowercase;
   * checked for the presence of a honeytoken (`fake_fs.contains_honeytoken`);
   * mapped to the MITRE table;
   * logged as a `command` or `honeytoken_used` event;
   * transmitted to the webhook (from the same thread).

File system:
* `core/fake_fs.py` stores the `path → content` map in memory.
* Directories are simulated by a separate `path → element list` map.
* Honeytokens are randomly generated values with the `_canary_` suffix. Each token has a category (`db_password`, `aws_key`, `api_token`). If such a string appears in the company's internal logs, it serves as proof of compromise specifically through the trap.

Supported shell commands (PoC): `ls`, `cat`, `cd`, `pwd`, `whoami`, `id`, `uname`, `hostname`, `ifconfig`, `ip`, `netstat`, `ps`, `history`, `wget`, `curl`, `echo`, `find`, `exit`, `logout`, `quit`. Remaining commands return `command not found` — this is plausible and forces the attacker to try other options, increasing the number of recorded events.

### 2.3. Lokasenna — Alerting and Post-Analytics

Has two roles:
1. **Real-time webhook (`core/webhook_notifier.py`)** — synchronously sends JSON to Slack or Microsoft Teams. Two payload formats are supported. If `webhook_url` is empty, the message is printed to the console (convenient for development).
2. **Post-analysis (`lokasenna/analyzer.py`)** — runs separately on the accumulated `events.jsonl` and generates a summary report: distribution of ATT&CK tactics and techniques, top IPs, authentication attempts, honeytoken usage facts, and the most frequent attacker commands.

The output is designed for rapid generation of an evidentiary base for CSIRT/CERT reports and facility security services.

### 2.4. Mitre Mapper

A simple dictionary `signature → (tactic, technique_id, description)`. Includes the most common reconnaissance commands, sensitive file read attempts, tooling delivery signs (`wget`, `curl`), trace cleanup (`rm -rf`, `history -c`), and three special pseudo-signatures:
* `__tcp_connect__` — for the connection event itself;
* `__auth_attempt__` — login attempt (Brute Force);
* `__honeytoken__` — fixing the usage of a canary value.

The current size of the table is about 25 entries. In commercial operation, it is advisable to move it to an external JSON and periodically update it from the official MITRE STIX feed.

## 3. Data Flows

```text
   event (dict)
        │
        ▼
   logger.log_event ──► events.jsonl
        │
        ▼
   mitre.map_event(signature)
        │
        ▼
   webhook.send_alert ──► Slack/Teams (HTTP POST)
```

All components are connected solely through core function calls — this makes each module autonomous and allows replacing, for example, the log storage backend (with SQLite, Elasticsearch, or Wazuh) without modifying the sensors.

## 4. Deployment Model

Recommended scheme for a virtual laboratory:
* VM-1 (trap): Ubuntu Server 22.04, Hveðrungr listening on ports 2222 and 2323. Address `192.168.56.10/24`.
* VM-2 (attacker): Kali Linux, utilities `nmap`, `hydra`, `nikto`, `metasploit`. Address `192.168.56.20/24`.
* VM-3 (analyst): A separate machine with a browser and access to Slack (or Teams) to receive alerts.

All three machines are connected via an isolated VirtualBox host-only adapter — this guarantees that the attacker from VM-2 will never access the real internet even if they find a way to escalate privileges within the trap.

In production deployment, the trap is recommended to be placed in a DMZ segment with unidirectional routing: inbound access to the trap is allowed, while outbound access from the trap (except for the webhook channel) is prohibited.

## 5. Why Such Architecture

* **Thread-based separation instead of processes.** The PoC should be resource-friendly: one connection = one thread. For scaling to thousands of connections/sec, it can be rewritten using `asyncio`, but for an educational prototype, `threading` provides simpler code and a transparent call stack in the logs.
* **Sockets instead of paramiko/AsyncSSH.** Full SSH emulation adds hundreds of lines of code, requires key pair generation, and is unnecessary for a PoC: for our purpose, the connection fact and a slowly trickling banner are sufficient.
* **JSON-Lines.** The `events.jsonl` file is trivially appended and read by any language; it can be immediately forwarded to ELK or Splunk via `filebeat`/`fluent-bit`.
* **Webhook instead of direct Telegram API.** Slack/Teams webhook is standardized and does not require bot registration; for an academic PoC, this is the shortest path to working alerting.

## 6. PoC Limitations

* Does not simulate a true SSH handshake — therefore, scanners of the `nmap -sV` class will identify the service as an "unknown tcp" rather than OpenSSH. For combat deployment, a paramiko-based module is required.
* Does not store binary artifacts (`wget` only simulates them for now).
* One thread per connection — a theoretical maximum of 200–500 concurrent sessions without migrating to `asyncio`.
* Webhook anti-flood is minimally implemented (the `alert_cooldown` field in the config is reserved, but a full event deduplicator is moved to `TODO`).

## 7. Future Work

* Move the SSH part to paramiko to correctly respond to a true SSH handshake.
* Implement a three-dimensional emulator of the HTTP "admin panel" (port 8080) as an additional trap layer.
* Connect a STIX/TAXII client for automatic updating of the ATT&CK dictionary.
* Integrate Wazuh as a centralized JSON event receiver.
