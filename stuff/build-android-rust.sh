#!/bin/bash

# Configuration
RUST_PROJECT_PATH="."
OUTPUT_DIR="target/android-libs"
FEATURES="stream-cipher,aead-cipher-extra,logging,local-flow-stat,local-dns,aead-cipher-2022"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/25.2.9519653}"  # Adjust this path

# Required target architectures and their corresponding Android targets
declare -A TARGETS=(
    ["arm"]="armv7-linux-androideabi"
    ["arm64"]="aarch64-linux-android"
    ["x86"]="i686-linux-android"
    ["x86_64"]="x86_64-linux-android"
)

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Function to setup Android targets
setup_android_targets() {
    for target in "${!TARGETS[@]}"; do
        rustup target add "${TARGETS[$target]}"
    done
}

# Build for all targets
build_all() {
    local profile="${1:-release}"
    
    for arch in "${!TARGETS[@]}"; do
        target="${TARGETS[$arch]}"
        echo "Building for $arch ($target)..."
        
        # Create output directory for this architecture
        mkdir -p "$OUTPUT_DIR/$arch"
        
        # Build the library
        cargo build --manifest-path="$RUST_PROJECT_PATH/Cargo.toml" \
            --target "$target" \
            --features "$FEATURES" \
            --no-default-features \
            --bin sslocal \
            --profile "$profile" \
            --target-dir "target"
            
        # Copy the built library to the output directory
        if [ "$profile" = "release" ]; then
            cp "target/$target/release/libsslocal.so" "$OUTPUT_DIR/$arch/"
        else
            cp "target/$target/debug/libsslocal.so" "$OUTPUT_DIR/$arch/"
        fi
    done
}

# Main execution
echo "Setting up Android targets..."
setup_android_targets

echo "Building libraries..."
build_all "release"

echo "Build complete! Libraries are in $OUTPUT_DIR/"
echo "To use these libraries in your Android project, copy the contents of $OUTPUT_DIR to:"
echo "app/src/main/jniLibs/ or core/src/main/jniLibs/"
