"""Simple smoke tests for basic logic without running real sockets."""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import logger, mitre_mapper
from lokanet import fake_fs


def test_mitre_basic():
    assert mitre_mapper.map_event("cat /etc/passwd").technique_id == "T1003.008"
    assert mitre_mapper.map_event("whoami").technique_id == "T1033"
    assert mitre_mapper.map_event("ls -la").technique_id == "T1083"
    assert mitre_mapper.map_event("wget http://x/y").technique_id == "T1105"
    assert mitre_mapper.map_event("__auth_attempt__").tactic == "Credential Access"
    print("test_mitre_basic OK")


def test_fake_fs():
    assert fake_fs.is_dir("/etc")
    assert fake_fs.file_exists("/etc/passwd")
    assert "root:x:0:0" in fake_fs.read_file("/etc/passwd")
    assert "Wint3rfell" in fake_fs.read_file("/root/.bash_history")
    assert fake_fs.contains_honeytoken(
        "PGPASSWORD=Wint3rfell!2024_canary_8f3a1 psql ...") == "db_password"
    print("test_fake_fs OK")


def test_logger():
    with tempfile.TemporaryDirectory() as tmp:
        logger.init_logger(tmp, "ev.jsonl", "t.log")
        ev = logger.log_event("test", "demo",
                              {"src_ip": "1.2.3.4", "info": "hello",
                               "mitre": {"tactic": "Discovery",
                                         "technique_id": "T1083",
                                         "description": "x"}})
        assert ev["module"] == "test"
        with open(os.path.join(tmp, "ev.jsonl"), encoding="utf-8") as f:
            line = json.loads(f.readline())
        assert line["src_ip"] == "1.2.3.4"
    print("test_logger OK")


if __name__ == "__main__":
    test_mitre_basic()
    test_fake_fs()
    test_logger()
    print("\nALL TESTS PASSED")
