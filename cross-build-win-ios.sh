#!/bin/bash

# Configuration
RUST_PROJECT_PATH="."
OUTPUT_DIR="target/cross-platform"
FEATURES="stream-cipher,aead-cipher-extra,logging,local-dns,aead-cipher-2022"
XCFRAMEWORK_NAME="SSLocal"

# Docker configuration
DOCKER_PRUNE_DAYS=7
MIN_DOCKER_SPACE_GB=10

# Ensure we're using bash
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
    exit
fi

# Apple platform targets
declare -A APPLE_TARGETS=(
    ["ios"]="aarch64-apple-ios"
    ["macos"]="x86_64-apple-darwin aarch64-apple-darwin"
#    ["tvos"]="aarch64-apple-tvos"
)
#declare -A APPLE_TARGETS=(
#    ["macos"]="x86_64-apple-darwin aarch64-apple-darwin"
#    ["ios"]="aarch64-apple-ios"
#    ["tvos"]="aarch64-apple-tvos"
#)

# Windows targets (to be built with Cross)
WINDOWS_TARGETS="x86_64-pc-windows-gnu i686-pc-windows-gnu"

check_docker_space() {
    echo "Checking Docker space..."

    # Get available space in Docker root directory
    local docker_root=$(docker info --format '{{.DockerRootDir}}')
    local available_space=$(df -BG "$docker_root" | awk 'NR==2 {print $4}' | sed 's/G//')

    echo "Available Docker space: ${available_space}GB"

    if [ "$available_space" -lt "$MIN_DOCKER_SPACE_GB" ]; then
        echo "Docker space is low. Cleaning up..."

        # Stop all running containers
        docker container stop $(docker container ls -q) 2>/dev/null || true

        # Remove unused containers, networks, images, and volumes
        docker system prune -af --volumes --filter "until=${DOCKER_PRUNE_DAYS}d"

        # Check space again
        available_space=$(df -BG "$docker_root" | awk 'NR==2 {print $4}' | sed 's/G//')
        if [ "$available_space" -lt "$MIN_DOCKER_SPACE_GB" ]; then
            echo "ERROR: Not enough Docker space available even after cleanup"
            exit 1
        fi
    fi
}

# Function to check required tools
check_dependencies() {
    local required_tools="cargo rustc xcodebuild docker"

    for tool in $required_tools; do
        if ! command -v $tool &> /dev/null; then
            echo "Error: Required tool '$tool' is not installed."
            exit 1
        fi
    done

    # Install Cross if not already installed
    if ! command -v cross &> /dev/null; then
        echo "Installing cross..."
        cargo install cross
    fi

    # Check Rust targets are installed
    for platform in "${!APPLE_TARGETS[@]}"; do
        for target in ${APPLE_TARGETS[$platform]}; do
            if ! rustup target list | grep -q "$target installed"; then
                echo "Installing Rust target $target..."
                rustup target add $target
            fi
        done
    done
}

# Function to build for Apple platforms (using native toolchain)
build_apple() {
    # Print the associative array contents for debugging
    echo "Available platforms and targets:"
    for platform in "${!APPLE_TARGETS[@]}"; do
        echo "Platform: $platform, Target: ${APPLE_TARGETS[$platform]}"
    done

    local platform=$1
    if [[ -z "${APPLE_TARGETS[$platform]}" ]]; then
        echo "Error: No targets found for platform $platform"
        return 1
    fi

    local targets="${APPLE_TARGETS[$platform]}"
    echo "Building targets for $platform: $targets"
    local framework_dir="$OUTPUT_DIR/$platform"
    local libs_dir="$framework_dir/libs"

    mkdir -p "$libs_dir"

    # Build for each architecture
    for target in $targets; do
        echo "Building for $target..."

        # Set platform-specific flags
        local rustflags=""
        case $platform in
            "macos")
                rustflags="-C link-arg=-undefined -C link-arg=dynamic_lookup"
                ;;
            "ios"|"tvos")
                rustflags="-C link-arg=-undefined -C link-arg=dynamic_lookup -C link-arg=-mios-version-min=12.0"
                ;;
        esac

        RUSTFLAGS="$rustflags" cargo build \
            --manifest-path="$RUST_PROJECT_PATH/Cargo.toml" \
            --target "$target" \
            --features "$FEATURES" \
            --bin sslocal \
            --release

        # Copy the library and create framework structure
        mkdir -p "$framework_dir/$XCFRAMEWORK_NAME.framework"
        cp "target/$target/release/sslocal" "$framework_dir/$XCFRAMEWORK_NAME.framework/$XCFRAMEWORK_NAME"
    done

    # Create Info.plist in the framework
    cat > "$framework_dir/$XCFRAMEWORK_NAME.framework/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$XCFRAMEWORK_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>com.shadowsocks.sslocal</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$XCFRAMEWORK_NAME</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>12.0</string>
</dict>
</plist>
EOF
}

# Function to build for Windows using Cross
build_windows() {
    # Ensure Docker is running
    if ! docker info > /dev/null 2>&1; then
        echo "Error: Docker is not running. Please start Docker and try again."
        exit 1
    fi

    # Build Cross.toml if it doesn't exist
    if [ ! -f "Cross.toml" ]; then
        cp cross-windows-config.toml Cross.toml
    fi

    for target in $WINDOWS_TARGETS; do
        echo "Building for $target..."

        # Build using Cross
        RUST_BACKTRACE=1 cross build \
            --manifest-path="$RUST_PROJECT_PATH/Cargo.toml" \
            --target "$target" \
            --features "$FEATURES" \
            --bin sslocal \
            --release

        # Create output directory and copy outputs
        mkdir -p "$OUTPUT_DIR/windows/$target"
        if [ -f "target/$target/release/sslocal.exe" ]; then
            cp "target/$target/release/sslocal.exe" "$OUTPUT_DIR/windows/$target/"
        fi
    done
}

# Function to create XCFramework
create_xcframework() {
    local xcframework_path="$OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"
    rm -rf "$xcframework_path"

    # Prepare framework arguments
    local framework_args=""

    # Add each platform's framework if it exists
    for platform in "${!APPLE_TARGETS[@]}"; do
        local framework_path="$OUTPUT_DIR/$platform/$XCFRAMEWORK_NAME.framework"
        if [ -d "$framework_path" ]; then
            if [ -z "$framework_args" ]; then
                framework_args="-framework $framework_path"
            else
                framework_args="$framework_args -framework $framework_path"
            fi
        fi
    done

    if [ -z "$framework_args" ]; then
        echo "Error: No frameworks found to create XCFramework"
        return 1
    fi

    echo "Creating XCFramework with command:"
    echo "xcodebuild -create-xcframework $framework_args -output $xcframework_path"

    xcodebuild -create-xcframework $framework_args -output "$xcframework_path"

    if [ $? -eq 0 ]; then
        echo "Successfully created XCFramework"
    else
        echo "Failed to create XCFramework"
        return 1
    fi
}

# Function to setup build environment
setup_environment() {
    # Pull Cross docker images in advance
    for target in $WINDOWS_TARGETS; do
        echo "Pulling Cross docker image for $target..."
        docker pull "ghcr.io/cross-rs/${target}:latest"
    done
}

# Main execution
echo "Checking dependencies..."
check_dependencies

#echo "Setting up build environment..."
#setup_environment

echo "Creating output directory..."
mkdir -p "$OUTPUT_DIR"

## Build for Apple platforms
#for platform in "${!APPLE_TARGETS[@]}"; do
#    echo "Building for platform: $platform"
#    build_apple "$platform"
#done

# Create XCFramework
echo "Creating XCFramework..."
create_xcframework

# Build for Windows using Cross
echo "Building for Windows using Cross..."
build_windows

echo "Build complete! Output is in $OUTPUT_DIR/"
echo "- XCFramework: $OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"
echo "- Windows binaries: $OUTPUT_DIR/windows/"