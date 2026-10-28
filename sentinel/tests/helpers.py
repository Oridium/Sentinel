from datetime import datetime, timedelta, timezone

from sentinel.models import AuthEvent


def event(seconds: int, *, ip: str = "192.0.2.10", host: str = "test-host",
          username: str = "demo", outcome: str = "failure", line: int = 1) -> AuthEvent:
    return AuthEvent(
        datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        host, ip, username, outcome, "password", 45000, False, "synthetic.log", line,
    )


def log_line(seconds: int = 0, *, host: str = "test-host", ip: str = "192.0.2.10",
             username: str = "demo", action: str = "Failed") -> str:
    return (f"2026-01-01T00:00:{seconds:02d}Z {host} sshd[42]: "
            f"{action} password for {username} from {ip} port 45000 ssh2\n")

