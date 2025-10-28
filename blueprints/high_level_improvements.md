# Implementation Blueprint Index

This directory now documents the architecture references that guide the concrete improvements committed to the project. Only
blueprints that remain relevant to the implemented work are listed below.

| # | Reference | Focus |
| --- | --- | --- |
| 1 | [Dual-Mode Ollama Containerization Strategy](dual-mode-ollama-containerization.md) | Run the agent in a Docker image that can either embed Ollama or attach to an external server. |
| 2 | **Network Reconnaissance Efficiency Notes** | Implemented directly in `nmap_agent.py` – adaptive host discovery, risk-driven vulnerability sweeps, and smarter fallbacks that prioritise actionable findings. |

The removed design notes (deployment pipelines, orchestration layers, scaling, modularity, observability, resilience, knowledge
sync, secret management, and operator tooling) are no longer required. The repository now favours real code that accelerates
finding hosts and vulnerabilities over speculative planning.
