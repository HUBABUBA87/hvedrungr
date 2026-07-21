"""
lokasenna.analyzer
------------------
Lokasenna auxiliary module — post-analysis of the accumulated event log.

Real-time alerting is handled directly by the Narfa and Lokanet modules
at the moment of the events (ensuring minimal latency). Lokasenna is responsible
for computing aggregated statistics, identifying recurring patterns,
and aggregating alerts for reporting.

Standalone run:
    python -m lokasenna.analyzer logs/events.jsonl
"""

import json
import os
import sys
from collections import Counter, defaultdict


def load_events(path: str):
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def summarize(events):
    """Returns a dictionary with summary analytics."""
    by_ip = Counter()
    by_tactic = Counter()
    by_technique = Counter()
    auth_attempts = defaultdict(int)
    honeytoken_hits = []
    cmd_counter = Counter()

    for e in events:
        ip = e.get("src_ip")
        if ip:
            by_ip[ip] += 1
        m = e.get("mitre") or {}
        if m.get("tactic"):
            by_tactic[m["tactic"]] += 1
        if m.get("technique_id"):
            by_technique[m["technique_id"]] += 1

        if e.get("event_type") == "auth_attempt" and ip:
            auth_attempts[ip] += 1
        if e.get("event_type") == "honeytoken_used":
            honeytoken_hits.append({
                "src_ip": ip, "token": e.get("honeytoken"),
                "time": e.get("timestamp")
            })
        if e.get("event_type") == "command":
            cmd = (e.get("command") or "").split()[:1]
            if cmd:
                cmd_counter[cmd[0]] += 1

    return {
        "total_events": len(events),
        "unique_sources": len(by_ip),
        "top_sources": by_ip.most_common(10),
        "tactics_distribution": by_tactic.most_common(),
        "techniques_distribution": by_technique.most_common(),
        "auth_attempts_per_ip": dict(auth_attempts),
        "honeytoken_hits": honeytoken_hits,
        "top_commands": cmd_counter.most_common(15),
    }


def print_report(summary: dict) -> None:
    print("=" * 60)
    print("Hveðrungr / Lokasenna — Threat Intelligence Report")
    print("=" * 60)
    print(f"Total events recorded : {summary['total_events']}")
    print(f"Unique source IPs     : {summary['unique_sources']}")

    print("\nTop sources:")
    for ip, n in summary["top_sources"]:
        print(f"  {ip:<20} {n} events")

    print("\nTactics distribution (MITRE ATT&CK):")
    for t, n in summary["tactics_distribution"]:
        print(f"  {t:<25} {n}")

    print("\nTechniques (top):")
    for t, n in summary["techniques_distribution"][:15]:
        print(f"  {t:<10} {n}")

    if summary["honeytoken_hits"]:
        print("\nHoneytoken usage detected:")
        for h in summary["honeytoken_hits"]:
            print(f"  {h['time']}  {h['src_ip']}  -> {h['token']}")

    if summary["auth_attempts_per_ip"]:
        print("\nAuth attempts per IP:")
        for ip, n in sorted(summary["auth_attempts_per_ip"].items(),
                            key=lambda x: -x[1]):
            print(f"  {ip:<20} {n}")

    if summary["top_commands"]:
        print("\nTop attacker commands:")
        for cmd, n in summary["top_commands"]:
            print(f"  {cmd:<15} {n}")
    print("=" * 60)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/events.jsonl"
    events = load_events(path)
    print_report(summarize(events))
