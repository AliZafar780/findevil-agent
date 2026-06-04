# FindEvil Agent — Docker Deployment
# Reproducible environment for autonomous DFIR analysis
FROM python:3.11-slim

LABEL description="FindEvil Agent — Autonomous DFIR MCP Server"
LABEL version="1.0.0"

# Install SIFT forensic tools
RUN apt-get update -qq && apt-get install -y -qq \
    sleuthkit \
    foremost \
    yara \
    tshark \
    tcpdump \
    binwalk \
    hashdeep \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/

RUN pip install --no-cache-dir -e ".[dev]"

# Install Volatility 3 + regipy
RUN pip install --no-cache-dir volatility3 regipy

# Create evidence/results directories
RUN mkdir -p /evidence/{disk,memory,network,cases} /results/{audit,carved,timelines,reports}

# Environment
ENV EVIDENCE_ROOT=/evidence
ENV RESULTS_ROOT=/results
ENV PYTHONUNBUFFERED=1

# Expose MCP port (for SSE mode)
EXPOSE 8080

# Default: run MCP server in stdio mode
ENTRYPOINT ["python", "-m", "src.server"]
