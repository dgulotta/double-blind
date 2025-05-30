double-blind
============

A demo of group signatures.

Running the demo
================
To install dependencies:
```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

To build the WebAssembly module:
```sh
cd double-blind-web
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen ../target/wasm32-unknown-unknown/release/double_blind_web.wasm --out-dir pkg --target web
```

Then the demo can be run using any web server.  For example,
```sh
cd pkg
python3 -m http.server
```
