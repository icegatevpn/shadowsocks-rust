cargo build --target aarch64-apple-ios --package shadowsocks-vpn --lib --release
cargo build --target x86_64-apple-ios  --package shadowsocks-vpn --lib --release 
cargo build --target aarch64-apple-ios-sim --package shadowsocks-vpn --lib --release
cp target/aarch64-apple-ios/release/libshadowsocks_vpn.a target/ios-libs/aarch64-apple-ios/libshadowsocks_vpn.a
cp target/x86_64-apple-ios/release/libshadowsocks_vpn.a target/ios-libs/x86_64-apple-ios/libshadowsocks_vpn.a
cp target/aarch64-apple-ios-sim/release/libshadowsocks_vpn.a target/ios-libs/aarch64-apple-ios-sim/libshadowsocks_vpn.a
libtool -static -o target/ios-libs/combined/libshadowsocks_vpn.a target/aarch64-apple-ios/release/libshadowsocks_vpn.a target/x86_64-apple-ios/release/libshadowsocks_vpn.a target/aarch64-apple-ios-sim/release/libshadowsocks_vpn.a
