"""ECS document builders. Each returns (data_stream, source) so callers can route docs to a stream."""
from __future__ import annotations

import ipaddress
import shlex
from datetime import datetime, timezone

from .org import Host

ECS_VERSION = "8.11.0"

Doc = tuple[str, dict]


def ts(dt: datetime) -> str:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"timestamp must be timezone-aware, got naive {dt!r}")
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _base(at: datetime, dataset: str, category: list[str], etype: list[str]) -> tuple[str, dict]:
    stream = f"logs-{dataset}-default"
    doc = {
        "@timestamp": ts(at),
        "ecs": {"version": ECS_VERSION},
        "data_stream": {"type": "logs", "dataset": dataset, "namespace": "default"},
        "event": {"kind": "event", "category": category, "type": etype, "dataset": dataset},
    }
    return stream, doc


def _split_args(command_line: str) -> list[str]:
    """Split like CommandLineToArgvW would: whitespace-separated, wrapping double quotes removed."""
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] == '"' else t for t in shlex.split(command_line, posix=False)]


def _host(h: Host) -> dict:
    return {"name": h.name, "ip": [h.ip], "os": {"type": h.os}, "type": "workstation" if h.tier == 2 else "server"}


_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _direction(dest_ip: str) -> str:
    # Not ip.is_private: Python counts the documentation ranges (198.51.100.0/24, 203.0.113.0/24) the lab uses for
    # internet addresses, the C2 among them, as private.
    addr = ipaddress.ip_address(dest_ip)
    return "internal" if any(addr in n for n in _RFC1918) else "egress"


def process_start(
    at: datetime,
    host: Host,
    user: str,
    name: str,
    executable: str,
    command_line: str,
    parent_name: str,
    parent_command_line: str = "",
    pid: int = 4120,
    ppid: int = 3980,
    args: list[str] | None = None,
) -> Doc:
    stream, doc = _base(at, "endpoint.events.process", ["process"], ["start"])
    doc["event"]["action"] = "start"
    doc["host"] = _host(host)
    doc["user"] = {"name": user}
    doc["process"] = {
        "name": name,
        "executable": executable,
        "command_line": command_line,
        "args": args if args is not None else _split_args(command_line),
        "pid": pid,
        "parent": {"name": parent_name, "command_line": parent_command_line, "pid": ppid},
    }
    return stream, doc


def auth_logon(
    at: datetime,
    host: Host,
    user: str,
    source_ip: str,
    logon_type: str,
    outcome: str = "success",
) -> Doc:
    stream, doc = _base(at, "system.security", ["authentication"], ["start"])
    doc["event"].update(
        {
            "action": "logged-in" if outcome == "success" else "logon-failed",
            "code": "4624" if outcome == "success" else "4625",
            "outcome": outcome,
            "provider": "Microsoft-Windows-Security-Auditing",
        }
    )
    doc["host"] = _host(host)
    doc["user"] = {"name": user}
    doc["source"] = {"ip": source_ip}
    doc["winlog"] = {"logon": {"type": logon_type}}
    return stream, doc


def network_flow(
    at: datetime,
    host: Host,
    dest_ip: str,
    dest_port: int,
    domain: str,
    bytes_out: int,
    bytes_in: int,
) -> Doc:
    stream, doc = _base(at, "network_traffic.flow", ["network"], ["connection"])
    doc["host"] = _host(host)
    doc["source"] = {"ip": host.ip, "bytes": bytes_out}
    doc["destination"] = {"ip": dest_ip, "port": dest_port, "domain": domain, "bytes": bytes_in}
    doc["network"] = {"transport": "tcp", "bytes": bytes_out + bytes_in, "direction": _direction(dest_ip)}
    return stream, doc


def dns_query(at: datetime, host: Host, domain: str, answer_ip: str) -> Doc:
    stream, doc = _base(at, "network_traffic.dns", ["network"], ["protocol"])
    doc["host"] = _host(host)
    doc["source"] = {"ip": host.ip}
    doc["dns"] = {
        "question": {"name": domain, "type": "A"},
        "answers": [{"data": answer_ip, "type": "A"}],
        "resolved_ip": [answer_ip],
    }
    return stream, doc


def email_received(
    at: datetime,
    recipient: str,
    sender: str,
    subject: str,
    attachment: str,
    verdict: str,
) -> Doc:
    stream, doc = _base(at, "email_gateway.log", ["email"], ["info"])
    doc["email"] = {
        "from": {"address": [sender]},
        "to": {"address": [recipient]},
        "subject": subject,
        "attachments": [{"file": {"name": attachment}}],
    }
    doc["email_gateway"] = {"verdict": verdict}
    return stream, doc
