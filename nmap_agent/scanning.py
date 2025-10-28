"""Nmap execution helpers and result parsing utilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple
import getpass
import subprocess


@dataclass(frozen=True)
class CommandSpec:
    name: str
    template: str


DEFAULT_COMMANDS: Dict[str, CommandSpec] = {
    "ping_discovery": CommandSpec("ping_discovery", "nmap -T5 -sn --max-retries 0 -oG - {target}"),
    "top_ports_scan": CommandSpec(
        "top_ports_scan",
        "nmap -T5 --max-retries 1 --host-timeout 20s -p {ports} -oG - {target}",
    ),
    "udp_top_ports_scan": CommandSpec(
        "udp_top_ports_scan", "nmap -T5 -sU --top-ports 50 --stats-every 20s -oG - {target}"
    ),
    "service_discovery": CommandSpec(
        "service_discovery", "nmap -T4 -sV -p {ports} -oG - {target}"
    ),
    "script_lookup": CommandSpec(
        "script_lookup", "nmap -T4 --script {scripts} -p {ports} -oN - {target}"
    ),
    "smart_discovery": CommandSpec(
        "smart_discovery",
        "nmap -T5 -sn -n -PR -PE -PP -PS21,22,80,135,139,443,3389 --min-rate 400 --max-retries 0 --stats-every 15s -oG - {target}",
    ),
    "aggressive_service_map": CommandSpec(
        "aggressive_service_map",
        "nmap -T5 -sS -sV --top-ports {top_ports} --defeat-rst-ratelimit --max-retries 1 --min-rate 400 --stats-every 20s -oG - {target}",
    ),
    "rich_vuln_scan": CommandSpec(
        "rich_vuln_scan",
        "nmap -T5 -sV --script vuln,default,safe --top-ports {top_ports} --max-retries 1 --defeat-rst-ratelimit --host-timeout 30s -oG - {target}",
    ),
    "udp_priority_scan": CommandSpec(
        "udp_priority_scan",
        "nmap -T5 -sU --top-ports {udp_top} --max-retries 1 --min-rate 200 --stats-every 20s -oG - {target}",
    ),
}


def execute_command(
    name: str,
    *,
    arguments: Dict[str, object],
    default_target: str,
    commands: Dict[str, CommandSpec] | None = None,
    timeout: int = 90,
) -> str:
    """Execute a named Nmap command and return combined stdout/stderr."""

    commands = commands or DEFAULT_COMMANDS
    if name not in commands:
        raise ValueError(f"Unknown command '{name}'")

    args = dict(arguments)
    args.setdefault("target", default_target)
    args.setdefault("ports", "22,80,443")
    args.setdefault("scripts", "http-title")
    args.setdefault("top_ports", 100)
    args.setdefault("udp_top", 75)

    def _coerce(value: object) -> object:
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(item) for item in value)
        return value

    fmt_args = {key: _coerce(value) for key, value in args.items()}
    command = commands[name].template.format(**fmt_args)

    process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
    output = (process.stdout + process.stderr).strip()
    if _requires_privileges(output):
        sudo_output = _try_sudo(command, timeout)
        if sudo_output is not None:
            return sudo_output
    return output


def _requires_privileges(output: str) -> bool:
    lowered = output.lower()
    return "root privileges" in lowered or "requires root" in lowered


def _try_sudo(command: str, timeout: int) -> str | None:
    try:
        password = getpass.getpass("Root password required for this scan (leave blank to skip): ")
    except (EOFError, KeyboardInterrupt):
        return None
    if not password:
        return None
    sudo_command = f"echo {password!r} | sudo -S {command}"
    result = subprocess.run(sudo_command, shell=True, capture_output=True, text=True, timeout=timeout)
    return (result.stdout + result.stderr).strip()


def parse_greppable_ports(output: str) -> Dict[str, Dict[str, object]]:
    """Parse Nmap greppable output and return host metadata."""

    hosts: Dict[str, Dict[str, object]] = {}
    for line in output.splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split("Ports:")
        if len(parts) != 2:
            continue
        host_section, ports_section = parts
        host_tokens = host_section.split()
        if len(host_tokens) < 2:
            continue
        ip = host_tokens[1]
        hosts.setdefault(ip, {"open_ports": [], "services": {}, "protocols": set()})
        for entry in ports_section.split(","):
            entry = entry.strip()
            if not entry or "/" not in entry:
                continue
            fragments = entry.split("/")
            try:
                port = int(fragments[0])
            except ValueError:
                continue
            protocol = fragments[2] if len(fragments) > 2 else "tcp"
            state = fragments[1]
            service = fragments[4] if len(fragments) > 4 else ""
            if state != "open":
                continue
            hosts[ip]["open_ports"].append(port)
            hosts[ip]["services"][port] = service
            hosts[ip]["protocols"].add(protocol)
        hosts[ip]["open_ports"].sort()
        hosts[ip]["protocols"] = sorted(hosts[ip]["protocols"])
    return hosts
