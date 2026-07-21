"""
lokanet.fake_fs
---------------
Simulation of a minimal Linux-like file system with honeytokens.

The file system is stored in memory as a dictionary {path: content}.
It includes three types of "decoys":

  1. /etc/passwd — a realistic list of users;
  2. /var/log/auth.log — several lines of previous "successful" logins;
  3. /root/.bash_history and /home/admin/.bash_history — commands containing
     lines with tokens and passwords (honeytokens).

Each token has a unique canary value that the system can track in external
channels. If such a token appears, for example, in the internal service logs,
it serves as proof of compromise specifically through the honeypot.
"""

from textwrap import dedent

# Canary tokens — unique strings that never appear in legitimate infrastructure.
# If someone attempts to use them, the system will definitely detect it.
HONEYTOKENS = {
    "db_password": "Wint3rfell!2024_canary_8f3a1",
    "aws_key":     "AKIAIOSFODNN7EXAMPLE_canary_2b7e",
    "api_token":   "ghp_canary_9XkPq2RvLm4NbHcTwQy3Z_8aFhJ",
}


def _passwd() -> str:
    return dedent("""\
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        admin:x:1000:1000:Administrator,,,:/home/admin:/bin/bash
        postgres:x:113:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
        """)


def _shadow() -> str:
    # Hash "stubs" that look like real sha-512 strings.
    return dedent("""\
        root:$6$XzpQ.q9F$YsW8K6KQOd0lQVqfQwH2y0xLrJv8oHcEHmkLZxN3rB1iqJ4F9Xr2sQ:19500:0:99999:7:::
        admin:$6$Bm3Az1Lp$N4Hk2C7e0o5q2V8/3F9b6sQz1JhYbHvE2gP4dF6tL3pQrSx9N0a:19510:0:99999:7:::
        postgres:$6$T1pQrSx9$F6tL3pQrSx9N0aN4Hk2C7e0o5q2V8/3F9b6sQz1JhYbHvE2gP4dF6:19200:0:99999:7:::
        """)


def _auth_log() -> str:
    return dedent("""\
        Nov 14 02:13:08 srv-fin-01 sshd[1042]: Accepted password for admin from 10.20.30.40 port 51722 ssh2
        Nov 14 02:13:08 srv-fin-01 sshd[1042]: pam_unix(sshd:session): session opened for user admin by (uid=0)
        Nov 14 02:54:12 srv-fin-01 sshd[1042]: pam_unix(sshd:session): session closed for user admin
        Nov 14 03:11:48 srv-fin-01 CRON[1101]: pam_unix(cron:session): session opened for user root by (uid=0)
        Nov 14 03:11:48 srv-fin-01 CRON[1101]: pam_unix(cron:session): session closed for user root
        Nov 14 04:02:01 srv-fin-01 sshd[1199]: Accepted publickey for admin from 10.20.30.41 port 49801 ssh2
        """)


def _bash_history_root() -> str:
    return dedent(f"""\
        cd /opt/backup
        ls -la
        tar -czf /var/backups/db_backup_$(date +%F).tgz /var/lib/postgresql/15/main/
        export PGPASSWORD='{HONEYTOKENS["db_password"]}'
        psql -h db-internal.local -U postgres -d billing -c "VACUUM ANALYZE;"
        unset PGPASSWORD
        history -c
        """)


def _bash_history_admin() -> str:
    return dedent(f"""\
        ssh deploy@stage.internal
        aws s3 ls s3://fin-reports/
        # AWS_ACCESS_KEY_ID={HONEYTOKENS["aws_key"]}
        curl -H "Authorization: token {HONEYTOKENS["api_token"]}" \\
            https://git.internal/api/v3/repos/finance/payroll/releases
        sudo systemctl restart billing.service
        exit
        """)


# Ready path -> content map
FS = {
    "/etc/passwd": _passwd(),
    "/etc/shadow": _shadow(),
    "/etc/hostname": "srv-fin-01\n",
    "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n\n",
    "/var/log/auth.log": _auth_log(),
    "/root/.bash_history": _bash_history_root(),
    "/home/admin/.bash_history": _bash_history_admin(),
}

# Directories for the ls command
DIRS = {
    "/": ["bin", "boot", "etc", "home", "lib", "opt", "root",
          "sbin", "tmp", "usr", "var"],
    "/etc": ["passwd", "shadow", "hostname", "issue", "ssh", "nginx"],
    "/home": ["admin"],
    "/home/admin": [".bash_history", ".bashrc", ".profile", ".ssh", "reports"],
    "/root": [".bash_history", ".bashrc", ".profile", ".ssh", "scripts"],
    "/var": ["log", "lib", "backups", "spool"],
    "/var/log": ["auth.log", "syslog", "kern.log", "nginx"],
}


def list_dir(path: str) -> list:
    path = path.rstrip("/") or "/"
    return sorted(DIRS.get(path, []))


def read_file(path: str) -> str:
    return FS.get(path, "")


def file_exists(path: str) -> bool:
    return path in FS


def is_dir(path: str) -> bool:
    p = path.rstrip("/") or "/"
    return p in DIRS


def contains_honeytoken(text: str) -> str:
    """Checks if the provided text contains any canary token.
    Returns the token name or an empty string."""
    if not text:
        return ""
    for name, value in HONEYTOKENS.items():
        if value in text:
            return name
    return ""
