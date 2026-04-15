FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# ---- System dependencies ----
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# ---- Install uv (official installer) ----
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# ---- Make uv system-wide ----
RUN mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx \
    && chmod +x /usr/local/bin/uv /usr/local/bin/uvx

# ---- Set workdir ----
WORKDIR /workspaces/thesis

# ---- Git safety ----
RUN git config --system --add safe.directory /workspaces/thesis