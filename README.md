# Hveðrungr — Cyber Threat Analysis Honeypot Prototype

A PoC implementation of a cyber deception system developed as a practical component for a research paper on cyber threat analysis.

## Overview

Hveðrungr is a medium-interaction honeypot consisting of three interconnected modules:

| Module | Essence | Concept |
|---|---|---|
| **Narfa fjöturr** | SSH tarpit on TCP port 2222 | Connection delay: sends the banner at 1 byte/sec, wasting the time of scanners and botnets |
| **Lokanet** | Fake shell on TCP port 2323 | Simulated file system featuring honeytokens (canary passwords, keys, API tokens) |
| **Lokasenna** | Event analyzer + webhook notifier | Maps attacker actions to MITRE ATT&CK, sends alerts to Slack / Teams |

Module names reference Norse mythology: 
* Hveðrungr is an alternate name for Loki; 
* Narfa fjöturr refers to Narfi's fetters; 
* Lokanet is Loki's net; Lokasenna is Loki's flyting.

## Installation

```text
git clone <repo>
cd hvedrungr
python -m venv .venv
source .venv/bin/activate         # Linux/macOS
# .venv\Scripts\activate          # Windows
pip install -r requirements.txt

Requires **Python 3.9+**. No external dependencies other than PyYAML and requests.
```
## Running

```text
python main.py                    # picks up config.yaml from the current directory
python main.py path/to/config.yaml # alternative configuration path
```
To stop — press Ctrl+C.

Logs will appear in the `logs/` directory:
* `events.jsonl` — structured events in JSON Lines format;
* `hvedrungr.log` — human-readable text log.

## Quick Verification

In another terminal:

### 1. Test Narfa fjöturr (slow banner delivery)

```text
nc 127.0.0.1 2222
```
### 2. Test Lokanet shell

```text
nc 127.0.0.1 2323
# login: admin
# password: any
# admin@srv-fin-01:/home/admin$ ls /etc
# admin@srv-fin-01:/home/admin$ cat /etc/passwd
# admin@srv-fin-01:/home/admin$ cat /root/.bash_history
# admin@srv-fin-01:/home/admin$ exit
```
### 3. Lokasenna analyzer report

```text
python -m lokasenna.analyzer logs/events.jsonl
```

## Configuration Parameters

File `config.yaml`:

```text
bind_host: "0.0.0.0"                # 127.0.0.1 for local tests

narfa:
  enabled: true
  port: 2222
  banner: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
  byte_delay_seconds: 1.0          # delay between banner bytes
  hold_seconds: 60                 # duration to hold the connection after the banner

lokanet:
  enabled: true
  port: 2323
  hostname: "srv-fin-01"
  username: "admin"

lokasenna:
  enabled: true
  webhook_url: ""                  # empty = output to console/log only
  webhook_type: "slack"            # slack | teams | none
  alert_cooldown_seconds: 5
```
## Slack / Teams Integration

1. In Slack: Create an Incoming Webhook in your workspace settings and copy the URL.
2. In Microsoft Teams: Add the "Incoming Webhook" connector to your channel (or set up a Power Automate flow) and copy the URL.
3. Paste the URL into `lokasenna.webhook_url` and set `webhook_type` (`slack` or `teams`).

## Project Structure

```text
hvedrungr/
├── main.py                  entry point
├── config.yaml              configuration
├── requirements.txt
├── core/
│   ├── logger.py            JSON and text logging
│   ├── mitre_mapper.py      MITRE ATT&CK mapping table
│   └── webhook_notifier.py  Slack / Teams notification sender
├── narfa/
│   └── tarpit.py            Narfa fjöturr module (SSH tarpit)
├── lokanet/
│   ├── fake_fs.py           fake file system + honeytokens
│   └── shell_server.py      Lokanet module (interactive shell)
├── lokasenna/
│   └── analyzer.py          post-analytics of events
├── logs/                    log directory (created automatically)
├── docs/
│   └── architecture.md      detailed architecture documentation
└── tests/
    └── test_basic.py        smoke tests
```
## Prototype Security

* All servers listen on **non-privileged ports** (>1024), meaning root privileges are not required.
* The trap does not execute real commands: all responses are static dictionary strings. There is no escape to the host OS.
* The file system is an in-memory object; nothing is written to physical disk files.
* Honeytokens are predefined canary values featuring the `_canary_` suffix.
* Deployment is recommended in an isolated network segment (DMZ or an isolated virtual machine).

## License

Developed for academic research and study purposes. Free use for learning and research is permitted.
