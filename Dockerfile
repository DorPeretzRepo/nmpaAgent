FROM python:3.11-slim

ARG OLLAMA_INSTALL_SCRIPT=https://ollama.com/install.sh

ENV OLLAMA_HOME=/root/.ollama \
    PATH="/usr/local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL ${OLLAMA_INSTALL_SCRIPT} | sh

WORKDIR /app

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY manifests ./manifests
COPY blueprints ./blueprints
COPY projectAgentCopilotRules ./projectAgentCopilotRules
COPY project_design.md ./project_design.md
COPY tasks.json ./tasks.json
COPY nmap_agent.py ./nmap_agent.py

RUN pip install --no-cache-dir requests

EXPOSE 11434

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "nmap_agent.py"]
