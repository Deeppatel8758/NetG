# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml uv.lock* README.md ./
COPY src/ ./src/

# Install dependencies using uv
RUN uv pip install --system --no-cache .

# Stage 2: Runtime
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install runtime system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source
COPY --from=builder /app/src ./src

# Create non-root user
RUN groupadd -r netguard && useradd -r -g netguard -d /app -s /sbin/nologin netguard \
    && chown -R netguard:netguard /app

USER netguard

EXPOSE 8080

CMD ["netguard", "run", "--config", "/app/config.yaml"]
