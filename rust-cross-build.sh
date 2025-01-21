#!/bin/bash

# Configuration
RUST_PROJECT_PATH="."
OUTPUT_DIR="target/android-libs"
FEATURES="stream-cipher,aead-cipher-extra,logging,local-flow-stat,local-dns,aead-cipher-2022"
NDK_VERSION="25"

# First, make sure we're using bash
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
    exit
fi

# Build targets
TARGETS="x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android"
# TARGETS="armv7-linux-androideabi"
declare -A ABI_MAP
ABI_MAP["x86_64-linux-android"]="x86_64"
ABI_MAP["aarch64-linux-android"]="arm64-v8a"
ABI_MAP["armv7-linux-androideabi"]="armeabi-v7a"
ABI_MAP["i686-linux-android"]="x86"

# Ensure cross is installed
if ! command -v cross &> /dev/null; then
    echo "Installing cross..."
    cargo install cross
fi

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Build for all targets
build_all() {
    local profile="${1:-release}"
    
    # Set NDK version for gcc/unwind handling
    export CARGO_NDK_MAJOR_VERSION="$NDK_VERSION"
    
     for target in $TARGETS; do
        abi="${ABI_MAP[$target]}"
        echo "Building for $target (Android ABI: $abi)..."
        
        # Create output directory for this architecture
        mkdir -p "$OUTPUT_DIR/$abi"
        
        # Build using cross
        RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-soname,libsslocal.so" \
        cross build \
            --manifest-path="$RUST_PROJECT_PATH/Cargo.toml" \
            --target "$target" \
            --features "$FEATURES" \
            --no-default-features \
            --bin sslocal \
            ${profile:+--release}
            
       # Determine the correct source path
        local bin_path
        if [ "$profile" = "release" ]; then
            bin_path="target/$target/release/sslocal"
        else
            bin_path="target/$target/debug/sslocal"
        fi
        
       # Copy and rename the binary as a shared library
        if [ -f "$bin_path" ]; then
            cp "$bin_path" "$OUTPUT_DIR/$abi/libsslocal.so"
            echo "Copied and renamed $bin_path to $OUTPUT_DIR/$abi/libsslocal.so"
        else
            echo "Warning: Built binary not found at $bin_path"
            echo "Looking for built files in target directory..."
            find "target/$target/${profile}" -type f -executable
        fi
    done
}

# Main execution
echo "Checking dependencies..."
check_dependencies

echo "Building libraries using cross..."
echo "Project path: $RUST_PROJECT_PATH"
build_all "release"

echo "Build complete! Libraries are in $OUTPUT_DIR/"
echo "You can now copy the contents of $OUTPUT_DIR to your Android project's jniLibs directory:"
echo "app/src/main/jniLibs/ or core/src/main/jniLibs/"
