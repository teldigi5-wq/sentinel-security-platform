"""Realistic file fixture -> normalized signed ingestion; no external hosts or root privileges."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sentinel.collectors.linux_ssh import (
    CollectorError, extract_source_ip, process_file, send_signed,
)
from test_api import client_for, post_event, auth

KEY = "k" * 48
IP = "198.51.100.42"


def log_line(ip=IP, *, username="someone", kind="password"):
    return (f"Oct 16 09:20:00 host sshd[431]: Failed {kind} for invalid user {username} "
            f"from {ip} port 43091 ssh2\n").encode()


def make_paths(tmp_path):
    source = tmp_path / "auth.log"
    state_dir = tmp_path / "private-cursor"
    state_dir.mkdir(mode=0o700)
    return source, state_dir / "ssh.json"


def pump(source: Path, state: Path, send, *, limit=1000):
    return process_file(source=source, state_path=state, asset_id="linux-host-1",
                        sensor_key=KEY, send=send, max_lines=limit)


def test_parser_normalizes_ips_and_discards_unrelated_logs():
    assert extract_source_ip(log_line()) == IP
    assert extract_source_ip(log_line("2001:db8::5", kind="publickey")) == "2001:db8::5"
    assert extract_source_ip(b"Oct 16 host sshd[30]: Accepted password for user from 192.0.2.1 port 999 ssh2\n") is None
    assert extract_source_ip(log_line("not-an-ip")) is None
    assert extract_source_ip(b"Untrusted string with SSH failed password text") is None


def test_normalized_events_do_not_expose_usernames_or_raw_log(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line(username="sensitive-user"))
    messages = []
    assert pump(source, state, lambda body, nonce: messages.append((body, nonce))) == (1, 1)
    data = json.loads(messages[0][0])
    assert set(data) == {"asset_id", "category", "action", "source_ip", "observed_at"}
    assert data["source_ip"] == IP
    assert "sensitive-user" not in messages[0][0].decode()
    assert len(messages[0][1]) == 32


def test_restart_cursor_and_append_are_idempotent(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line())
    reported = []
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 1)
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (0, 0)
    with source.open("ab") as stream:
        stream.write(log_line())
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 1)
    assert reported[0] != reported[1]
    assert state.stat().st_mode & 0o777 == 0o600


def test_transport_failure_does_not_discard_unsent_record(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line())
    observed = []
    def failing_send(body, nonce):
        observed.append(nonce)
        raise CollectorError("simulated transport failure")
    with pytest.raises(CollectorError, match="transport"):
        pump(source, state, failing_send)
    assert pump(source, state, lambda body, nonce: observed.append(nonce)) == (1, 1)
    assert observed[0] == observed[1]  # resend uses a deterministic replay-resistant nonce


def test_partial_final_line_remains_uncommitted(tmp_path):
    source, state = make_paths(tmp_path)
    full = log_line()
    source.write_bytes(full + full[:-1])
    reported = []
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 1)
    with source.open("ab") as stream:
        stream.write(b"\n")
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 1)
    assert len(set(reported)) == 2


def test_rotation_and_truncation_are_detected(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line())
    reported = []
    pump(source, state, lambda body, nonce: reported.append(nonce))
    source.rename(tmp_path / "auth.log.1")
    source.write_bytes(log_line())
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 1)
    assert len(set(reported)) == 2
    # Truncation is detected if stored offset exceeds new file size.
    source.write_bytes(b"\n")
    assert pump(source, state, lambda body, nonce: reported.append(nonce)) == (1, 0)


def test_untrusted_file_paths_are_rejected(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line())
    source.chmod(0o666)
    with pytest.raises(CollectorError, match="not writable"):
        pump(source, state, lambda body, nonce: None)
    source.chmod(0o600)
    link = tmp_path / "auth-link"
    link.symlink_to(source)
    with pytest.raises(CollectorError):
        pump(link, state, lambda body, nonce: None)
    state.parent.chmod(0o755)
    with pytest.raises(CollectorError, match="private"):
        pump(source, state, lambda body, nonce: None)


def test_cursor_corruption_is_fail_closed(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line())
    state.write_text('{"offset": "invalid"}')
    state.chmod(0o600)
    with pytest.raises(CollectorError, match="Cursor"):
        pump(source, state, lambda body, nonce: None)


def test_oversized_line_is_not_silently_skipped(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(b"x" * 17000 + b"\n")
    with pytest.raises(CollectorError, match="Oversized"):
        pump(source, state, lambda body, nonce: None)


def test_disallows_non_local_network_destinations():
    with pytest.raises(CollectorError, match="literal loopback"):
        send_signed(raw=b"{}", nonce="a" * 32, sensor_id="lab-one",
                    sensor_key=KEY, host="203.0.113.17", port=8000)


def test_fixture_end_to_end_creates_real_detected_alert(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line() * 5)
    client, _ = client_for(tmp_path)
    received = []
    def in_process_signed_sender(raw: bytes, nonce: str):
        result = post_event(client, raw=raw, nonce=nonce)
        assert result.status_code in (202, 409), result.text
        received.append(result.status_code)
    assert pump(source, state, in_process_signed_sender) == (5, 5)
    alerts = client.get("/api/v1/alerts", headers=auth()).json()
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "auth-failure-burst-v1"
    assert alerts[0]["evidence_count"] == 5
    assert client.get("/api/v1/audit/integrity", headers=auth()).json()["valid"]
    assert pump(source, state, in_process_signed_sender) == (0, 0)
    assert received == [202] * 5


def test_truncation_reenrolls_generation_to_avoid_nonce_collision(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line() * 2)
    nonces = []
    assert pump(source, state, lambda body, nonce: nonces.append(nonce)) == (2, 2)
    # Same inode; shorter log after truncation must not replay first-line nonce.
    source.write_bytes(log_line())
    assert pump(source, state, lambda body, nonce: nonces.append(nonce)) == (1, 1)
    assert len(set(nonces)) == 3


def test_first_start_tails_log_by_default_when_selected(tmp_path):
    source, state = make_paths(tmp_path)
    source.write_bytes(log_line() * 5)
    nonces = []
    assert process_file(source=source, state_path=state, asset_id="linux-host-1",
                        sensor_key=KEY, send=lambda body, nonce: nonces.append(nonce),
                        start_at_end=True) == (0, 0)
    with source.open("ab") as stream:
        stream.write(log_line())
    assert process_file(source=source, state_path=state, asset_id="linux-host-1",
                        sensor_key=KEY, send=lambda body, nonce: nonces.append(nonce),
                        start_at_end=True) == (1, 1)
    assert len(nonces) == 1
