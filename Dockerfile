# Stage 1: Builder — install dependencies and download model
FROM python:3.12-slim AS builder

# Install system packages needed for compiling native extensions
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch first (avoids pulling ~2.5GB GPU wheels)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install yara-python for YARA signature scanning
RUN pip install --no-cache-dir "yara-python>=4.3"

# Copy project files and install with all optional dependencies
COPY . /src
WORKDIR /src
RUN pip install --no-cache-dir ".[all]"

# Download the sentence-transformer model at build time for offline use
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2', cache_folder='/opt/models')"

# Download spaCy model required by presidio-analyzer for PII detection
RUN python -m spacy download en_core_web_lg


# Stage 2: Runtime — minimal image for running the validator
FROM python:3.12-slim AS runtime

# OCI image metadata labels
LABEL org.opencontainers.image.title="ai-artifact-risk-validator" \
      org.opencontainers.image.description="AI Artifact Risk Validator - scan AI artifacts for security, performance, quality, compliance, and operational risks" \
      org.opencontainers.image.url="https://github.com/ai-artifact-validator/ai-artifact-risk-validator" \
      org.opencontainers.image.source="https://github.com/ai-artifact-validator/ai-artifact-risk-validator" \
      org.opencontainers.image.licenses="MIT"

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Copy entry point scripts from builder
COPY --from=builder /usr/local/bin/ai-artifact-validator /usr/local/bin/ai-artifact-validator

# Copy pre-downloaded ML model from builder
COPY --from=builder /opt/models /opt/models

# Create non-root user for runtime
RUN useradd --create-home --uid 1000 validator

# Set environment variables for offline model usage and Python behavior
ENV SENTENCE_TRANSFORMERS_HOME=/opt/models \
    HF_HUB_OFFLINE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory for artifact scanning
WORKDIR /workspace

# Switch to non-root user
USER validator

# Set entrypoint to the CLI tool; default command shows help
ENTRYPOINT ["ai-artifact-validator"]
CMD ["--help"]
