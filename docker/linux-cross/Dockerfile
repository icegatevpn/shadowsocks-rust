# rust-cross-x86_64
# Use Ubuntu 22.04 as the base image (has GCC 12 available)
FROM ubuntu:22.04

# Install dependencies
RUN apt update && apt install -y \
    build-essential \
    gcc-12 g++-12 \
    curl \
    pkg-config \
    ca-certificates \
    sqlite3 libsqlite3-dev \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust using rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Add Rust target for x86_64-unknown-linux-gnu
RUN rustup target add x86_64-unknown-linux-gnu
# Set working directory
WORKDIR /build

# Default command to show versions
CMD ["bash", "-c", "gcc --version && rustc --version && sqlite3 --version"]