"""High-level entry points for the polished Nmap agent."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Mapping
import time
import json
import sys

from . import attack_vectors
from . import exploits as exploit_module
from . import scanning
from .config import AgentPaths, AgentSettings, load_paths, load_settings
from .ollama import OllamaStatus, ensure_ollama
from .state import JsonStore

__all__ = [
    "PORT_HISTORY",
    "VENDOR_CACHE",
    "EXPLOIT_HISTORY",
    "ATTACK_VECTOR_CATALOG_FILE",
    "parse_open_ports_enhanced",
    "build_attack_vector_catalog",
    "refresh_attack_vector_catalog",
    "plan_exploit_actions",
    "request_and_execute_exploit",
    "execute_nmap",
    "run_agent",
]


_PATHS: AgentPaths = load_paths()
_SETTINGS: AgentSettings = load_settings()

_VENDOR_STORE = JsonStore(_PATHS.vendor_cache_file, default=dict)
_PORT_STORE = JsonStore(_PATHS.port_history_file, default=dict)
_EXPLOIT_STORE = JsonStore(_PATHS.exploit_log_file, default=list)

VENDOR_CACHE: Dict[str, str] = _VENDOR_STORE.load()
PORT_HISTORY: Dict[str, Dict[str, object]] = _PORT_STORE.load()
EXPLOIT_HISTORY: list[Dict[str, object]] = _EXPLOIT_STORE.load()

ATTACK_VECTOR_CATALOG_FILE = str(_PATHS.attack_vector_catalog_file)
DEFAULT_TARGET = _SETTINGS.default_target
AUTO_APPROVE_EXPLOITS = _SETTINGS.auto_approve_exploits


if not _SETTINGS.skip_ollama_check:
    OLLAMA_STATUS: OllamaStatus = ensure_ollama(_SETTINGS)
else:
    OLLAMA_STATUS = OllamaStatus(base_url=_SETTINGS.ollama_base_url, reachable=False, used_remote=False)


def parse_open_ports_enhanced(output: str) -> Dict[str, Dict[str, object]]:
    """Parse raw Nmap output, update caches, and return enriched host metadata."""

    parsed = attack_vectors.parse_open_ports_enhanced(output, vendor_cache=VENDOR_CACHE)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for target, meta in parsed.items():
        open_ports = list(meta.get("open_ports", []))
        PORT_HISTORY[target] = {
            "last_seen": timestamp,
            "open_ports": open_ports,
            "tcp_ports": open_ports,
            "udp_ports": [],
            "protocols": meta.get("protocols", []),
            "risk_score": int(meta.get("risk_score", 0)),
            "services": meta.get("services", {}),
            "risk_factors": meta.get("risk_factors", {}),
            "vendor": meta.get("vendor"),
        }
    _PORT_STORE.save()
    _VENDOR_STORE.save()
    return parsed


def build_attack_vector_catalog() -> Dict[str, object]:
    hosts: Dict[str, Dict[str, object]] = {}
    for target, meta in PORT_HISTORY.items():
        hosts[target] = {
            "open_ports": meta.get("open_ports", []),
            "services": meta.get("services", {}),
            "protocols": meta.get("protocols", []),
            "risk_factors": meta.get("risk_factors", {}),
            "risk_score": meta.get("risk_score", 0),
        }
    return attack_vectors.build_attack_vector_catalog(hosts)


def refresh_attack_vector_catalog() -> Path:
    catalog = build_attack_vector_catalog()
    path = _PATHS.attack_vector_catalog_file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog, indent=2))
    return path


def plan_exploit_actions(target: str) -> list[Dict[str, object]]:
    host_meta = PORT_HISTORY.get(target)
    if not host_meta:
        return []
    return exploit_module.build_exploit_plans(target, host_meta, exploits_dir=_PATHS.exploit_dir)


def request_and_execute_exploit(plan: Mapping[str, object], auto_approve: bool | None = None) -> str | None:
    auto = AUTO_APPROVE_EXPLOITS if auto_approve is None else auto_approve
    result = exploit_module.execute_exploit_plan(plan, auto_approve=auto, history=EXPLOIT_HISTORY)
    _EXPLOIT_STORE.save()
    return result


def execute_nmap(name: str, **arguments: object) -> str:
    return scanning.execute_command(name, arguments=dict(arguments), default_target=DEFAULT_TARGET)


def run_agent() -> None:
    """Simple CLI loop that showcases core capabilities."""

    print("Polished Nmap agent ready.")
    if OLLAMA_STATUS.reachable:
        source = "remote" if OLLAMA_STATUS.used_remote else "embedded"
        print(f"Ollama backend detected via {source} endpoint at {OLLAMA_STATUS.base_url}.")
    else:
        print("Ollama endpoint not reachable; LLM-guided planning disabled.")
    print("State directory:", _PATHS.state_dir)
    print("Default target:", DEFAULT_TARGET)
    print()
    print("Use execute_nmap(<command>) to run accelerated scans.")
    print("Feed outputs into parse_open_ports_enhanced() to update intelligence.")
    print("Call refresh_attack_vector_catalog() to write the current attack vector catalog.")


# Convenience alias for backwards compatibility
request_exploit_execution = request_and_execute_exploit
