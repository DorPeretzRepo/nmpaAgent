# Dual-Mode Ollama Containerization Strategy

## Objective
Deliver a single Docker image that can either host an embedded Ollama server or attach to an external Ollama instance so the
agent works in both isolated and connected environments without manual rebuilding.

## Architecture Overview
- `Dockerfile` installs Nmap, Python dependencies, and the Ollama CLI in one image.
- `docker-entrypoint.sh` inspects the environment at runtime to decide whether to connect to a remote Ollama endpoint or launch
the bundled server.
- Health probes reuse the existing agent `check_ollama()` routine, which now honours `OLLAMA_BASE_URL`, `OLLAMA_REMOTE_URL`, and
`OLLAMA_MODE` configuration.

## Key Components
- `Dockerfile` based on `python:3.11-slim` with inline installation of Ollama binaries and `nmap`.
- `docker-entrypoint.sh` for connection negotiation (`remote → fallback → embedded`).
- Environment variables: `OLLAMA_MODE`, `OLLAMA_REMOTE_URL`, `OLLAMA_BASE_URL`, `OLLAMA_AUTO_START`, and `NMAP_DEFAULT_TARGET`.

## Implementation Guide
1. Build the container with `docker build -t nmap-ollama-agent .`.
2. Run in **remote** mode:
   ```bash
   docker run -e OLLAMA_MODE=remote -e OLLAMA_REMOTE_URL=http://ollama.example:11434 \
     nmap-ollama-agent python nmap_agent.py "scan 10.0.0.0/24"
   ```
3. Run in **embedded** mode (default):
   ```bash
   docker run --rm -p 11434:11434 nmap-ollama-agent
   ```
   The entrypoint launches `ollama serve` in the background and waits for it to become available.
4. Override the scan target for air-gapped assessments with `-e NMAP_DEFAULT_TARGET=10.1.0.0/16`.

## Effectiveness Metrics
- Time to first successful inference when switching between remote and embedded modes.
- Ability to keep scanning when remote Ollama endpoints are unavailable (automatic fallback to embedded mode).
- Consistent network scan throughput thanks to identical runtime environments across deployments.
