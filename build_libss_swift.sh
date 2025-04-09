cargo build --target aarch64-apple-ios --package ss_swift --release
cargo build --target x86_64-apple-ios  --package ss_swift --release 
cargo build --target aarch64-apple-ios-sim --package ss_swift --release
libtool -static -o libss_swift.a target/aarch64-apple-ios/release/libss_swift.a target/x86_64-apple-ios/release/libss_swift.a target/aarch64-apple-ios-sim/release/libss_swift.a
