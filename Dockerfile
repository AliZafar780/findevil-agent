# ─────────────────────────────────────────────────────────────────
# FindEvil Agent — Multi-stage Dockerfile
# Builds a reproducible DFIR analysis environment with all tools.
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: Python Dependencies ────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip install --no-cache-dir -e .[dev,full]

# ── Stage 2: Full Tool Image ────────────────────────────────────
FROM ubuntu:24.04

LABEL maintainer="Ali Zafar"
LABEL description="FindEvil Agent — Autonomous DFIR Analysis"
LABEL version="2.1.1"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV EVIDENCE_ROOT=/evidence
ENV RESULTS_ROOT=/results

# Install system dependencies and forensic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core forensic tools
    sleuthkit \
    foremost \
    yara \
    tshark \
    binutils \
    bulk-extractor \
    binwalk \
    hashdeep \
    # Python & system
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    file \
    xxd \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create evidence and results directories
RUN mkdir -p /evidence/{disk,memory,network,cases} \
    /results/{audit,carved,timelines,reports}

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
WORKDIR /app
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .[full]

# Create non-root user for security
RUN useradd -m -s /bin/bash findevil && \
    chown -R findevil:findevil /evidence /results /app
USER findevil

# Expose MCP SSE port (if using SSE transport)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -m src.cli --version || exit 1

# Default: run MCP server
ENTRYPOINT ["python3", "-m", "src.server"]
CMD []
