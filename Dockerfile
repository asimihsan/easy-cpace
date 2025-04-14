FROM ubuntu:latest

# Install dependencies
RUN apt-get update && apt-get -y --no-install-recommends install \
    sudo curl git ca-certificates build-essential \
    cmake ninja-build clang-format clang-tidy \
    && rm -rf /var/lib/apt/lists/*

# Set up Mise environment
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV MISE_DATA_DIR="/mise"
ENV MISE_CONFIG_DIR="/mise"
ENV MISE_CACHE_DIR="/mise/cache"
ENV MISE_INSTALL_PATH="/usr/local/bin/mise"
ENV PATH="/mise/shims:$PATH"

# Install Mise
RUN curl https://mise.run | sh

# Create a working directory
WORKDIR /app

# Copy only necessary files for Mise setup
COPY mise.toml Justfile ./

# Run initial setup
RUN mise trust && mise install

# Copy the rest of the project
COPY . .

# Run the CI checks (build, test, lint, benchmark)
RUN mise x -- just ci

# Default command
CMD ["/bin/bash"]
