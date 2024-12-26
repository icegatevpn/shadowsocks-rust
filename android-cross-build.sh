#!/opt/homebrew/bin/bash

# export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/27.0.12077973

# Configuration
RUST_PROJECT_PATH="."
OUTPUT_DIR="target/android-libs"
FEATURES="stream-cipher,aead-cipher-extra,aead-cipher-2022,local"
NDK_VERSION="25"

# First, make sure we're using bash
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
    exit
fi

# Build targets
TARGETS="x86_64-linux-android aarch64-linux-android armv7-linux-androideabi i686-linux-android"
# TARGETS="aarch64-linux-android"
declare -A ABI_MAP
ABI_MAP["x86_64-linux-android"]="x86_64"
ABI_MAP["aarch64-linux-android"]="arm64-v8a"
ABI_MAP["armv7-linux-androideabi"]="armeabi-v7a"
ABI_MAP["i686-linux-android"]="x86"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Build for all targets
build_all() {
    local profile="${1:-release}"

     for target in $TARGETS; do
        abi="${ABI_MAP[$target]}"
        echo "Building for $target (Android ABI: $abi)..."
        
        # Create output directory for this architecture
        mkdir -p "$OUTPUT_DIR/$abi"
        
        # Build using cross

        cargo ndk --platform 25 \
              --target "$target" \
               build \
              --package shadowsocks-vpn \
              --no-default-features \
              --features "$FEATURES" \
              --release
            
       # Determine the correct source path
        local lib_path
        if [ "$profile" = "release" ]; then
            lib_path="target/$target/release/libshadowsocks_vpn.so"
        else
            lib_path="target/$target/debug/libshadowsocks_vpn.so"
        fi
        
       # Copy and rename the binary as a shared library
        if [ -f "$lib_path" ]; then
            cp "$lib_path" "$OUTPUT_DIR/$abi/libshadowsocks_vpn.so"
            echo "Copied from $lib_path to $OUTPUT_DIR/$abi/libshadowsocks_vpn.so"

            cp "$lib_path" "/Users/enoch.carter/IceGate/client/android/app/src/main/jniLibs/$abi/libshadowsocks_vpn.so"
            echo "** Copied to /Users/enoch.carter/IceGate/client/android/app/src/main/jniLibs/$abi/libshadowsocks_vpn.so"
        else
            echo "Warning: Built library not found at $lib_path"
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
