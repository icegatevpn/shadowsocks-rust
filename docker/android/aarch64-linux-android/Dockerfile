FROM ghcr.io/cross-rs/aarch64-linux-android:latest

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends \
    build-essential \
    cmake \
    nasm \
    llvm-8-dev \
    libclang-8-dev \
    clang-8 \
    mingw-w64 \
    mingw-w64-tools \
    curl \
    unzip \
    git \
    ca-certificates \
    && git config --global --add safe.directory '*' \
    && rm -rf /var/lib/apt/lists/* /tmp/*
    
    
# Download and build SQLite for Windows cross-compilation
WORKDIR /tmp
RUN update-ca-certificates && \
    curl -L 'https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip' -o sqlite.zip && \
    unzip sqlite.zip && \
    cd sqlite-amalgamation-3450100 && \
    x86_64-w64-mingw32-gcc -c sqlite3.c -o sqlite3.o && \
    x86_64-w64-mingw32-ar rcs libsqlite3.a sqlite3.o && \
    cp libsqlite3.a /usr/x86_64-w64-mingw32/lib/ && \
    i686-w64-mingw32-gcc -c sqlite3.c -o sqlite3_32.o && \
    i686-w64-mingw32-ar rcs libsqlite3_32.a sqlite3_32.o && \
    cp libsqlite3_32.a /usr/i686-w64-mingw32/lib/libsqlite3.a && \
    cd .. && \
    rm -rf sqlite-amalgamation-3450100 sqlite.zip

ENV GOCACHE=/tmp