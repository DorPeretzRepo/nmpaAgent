"""Configuration utilities for the Nmap agent."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class AgentPaths:
    """Collection of filesystem locations used by the agent."""

    state_dir: Path
    exploit_dir: Path
    vendor_cache_file: Path
    port_history_file: Path
    attack_vector_catalog_file: Path
    exploit_log_file: Path
    tasks_log_file: Path
    last_run_summary_file: Path
    database_file: Path


@dataclass(frozen=True)
class AgentSettings:
    """Environment-derived runtime configuration for the agent."""

    ollama_base_url: str
    ollama_remote_url: str | None
    ollama_mode: str
    ollama_auto_start: bool
    ollama_health_timeout: float
    skip_ollama_check: bool
    default_target: str
    auto_approve_exploits: bool


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def load_paths() -> AgentPaths:
    state_dir = Path(os.getenv("NMAP_AGENT_STATE_DIR", ".")).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)

    exploit_dir = Path(
        os.getenv("NMAP_AGENT_EXPLOITS_DIR", state_dir / "exploits")
    ).expanduser().resolve()
    exploit_dir.mkdir(parents=True, exist_ok=True)

    return AgentPaths(
        state_dir=state_dir,
        exploit_dir=exploit_dir,
        vendor_cache_file=state_dir / "vendors_cache.json",
        port_history_file=state_dir / "ports_history.json",
        attack_vector_catalog_file=state_dir / "attack_vectors.json",
        exploit_log_file=state_dir / "exploit_history.json",
        tasks_log_file=state_dir / "tasks.json",
        last_run_summary_file=state_dir / "last_run_summary.json",
        database_file=state_dir / "nmap_agent.db",
    )


def load_settings() -> AgentSettings:
    return AgentSettings(
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_remote_url=os.getenv("OLLAMA_REMOTE_URL"),
        ollama_mode=os.getenv("OLLAMA_MODE", "auto").lower(),
        ollama_auto_start=_bool_env("OLLAMA_AUTO_START", True),
        ollama_health_timeout=float(os.getenv("OLLAMA_HEALTH_TIMEOUT", "4")),
        skip_ollama_check=_bool_env("OLLAMA_SKIP_CHECK", False),
        default_target=os.getenv("NMAP_DEFAULT_TARGET", "192.168.1.0/24"),
        auto_approve_exploits=_bool_env("NMAP_AGENT_AUTO_APPROVE_EXPLOITS", False),
    )
