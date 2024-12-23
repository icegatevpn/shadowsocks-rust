ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

ARG DEBIAN_FRONTEND=noninteractive
ARG NDK_VERSION=25

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

# Create necessary directories first
RUN mkdir -p /android-ndk/sysroot/usr/lib/aarch64-linux-android

# Download and extract Android NDK
#WORKDIR /tmp
#RUN curl -L https://dl.google.com/android/repository/android-ndk-r${NDK_VERSION}-linux.zip -o android-ndk.zip && \
#    unzip android-ndk.zip && \
#    rm android-ndk.zip && \
#    mv android-ndk-r${NDK_VERSION} /opt/android-ndk

# Copy necessary libraries from NDK
#RUN cp -r /opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/* /android-ndk/sysroot/usr/lib/aarch64-linux-android/

# Download and build SQLite for Android cross-compilation
WORKDIR /tmp
RUN update-ca-certificates && \
    curl -L 'https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip' -o sqlite.zip && \
    unzip sqlite.zip && \
    cd sqlite-amalgamation-3450100 && \
#        x86_64-w64-mingw32-gcc -c sqlite3.c -o sqlite3.o && \
#        x86_64-w64-mingw32-ar rcs libsqlite3.a sqlite3.o && \
#        cp libsqlite3.a /usr/x86_64-w64-mingw32/lib/ && \
#        i686-w64-mingw32-gcc -c sqlite3.c -o sqlite3_32.o && \
#        i686-w64-mingw32-ar rcs libsqlite3_32.a sqlite3_32.o && \
#        cp libsqlite3_32.a /usr/i686-w64-mingw32/lib/libsqlite3.a && \
    aarch64-linux-android-gcc -c sqlite3.c -o sqlite3.o && \
    aarch64-linux-android-ar rcs libsqlite3.a sqlite3.o && \
    cp libsqlite3.a /android-ndk/sysroot/usr/lib/aarch64-linux-android/ && \
    cd .. && \
    rm -rf sqlite-amalgamation-3450100 sqlite.zip

# Make sure the libraries are in the linker search path
#ENV CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-L /android-ndk/sysroot/usr/lib/aarch64-linux-android"
#ENV LD_LIBRARY_PATH="/android-ndk/sysroot/usr/lib/aarch64-linux-android:${LD_LIBRARY_PATH}"

# Add NDK tools to PATH
#ENV PATH="/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:${PATH}"

ENV GOCACHE=/tmp
