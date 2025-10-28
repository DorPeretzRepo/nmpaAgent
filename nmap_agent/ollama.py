"""Utilities for locating and validating an Ollama backend."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
import subprocess
import time
from typing import Callable

import requests

from .config import AgentSettings


@dataclass
class OllamaStatus:
    base_url: str
    reachable: bool
    used_remote: bool


ProbeFn = Callable[[str, float], bool]


def _is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if not host:
        return True
    return host in {"127.0.0.1", "localhost", "0.0.0.0"} or host.endswith(".local")


def _default_probe(url: str, timeout: float) -> bool:
    try:
        response = requests.get(f"{url}/api/tags", timeout=timeout)
        return response.status_code == 200
    except Exception:
        return False


def ensure_ollama(settings: AgentSettings, probe: ProbeFn = _default_probe) -> OllamaStatus:
    """Validate connectivity to Ollama, optionally booting a local instance."""

    preferred = (settings.ollama_remote_url or settings.ollama_base_url).rstrip("/")

    if settings.ollama_remote_url and probe(preferred, settings.ollama_health_timeout):
        return OllamaStatus(base_url=preferred, reachable=True, used_remote=True)

    if settings.ollama_mode == "remote" and not settings.ollama_auto_start:
        return OllamaStatus(base_url=preferred, reachable=False, used_remote=True)

    local_url = "http://127.0.0.1:11434"
    if probe(local_url, settings.ollama_health_timeout):
        return OllamaStatus(base_url=local_url, reachable=True, used_remote=False)

    if not settings.ollama_auto_start:
        return OllamaStatus(base_url=local_url, reachable=False, used_remote=False)

    subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(24):
        time.sleep(0.5)
        if probe(local_url, 1):
            return OllamaStatus(base_url=local_url, reachable=True, used_remote=False)
    return OllamaStatus(base_url=local_url, reachable=False, used_remote=False)
