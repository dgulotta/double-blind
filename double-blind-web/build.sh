cargo build --release --target wasm32-unknown-unknown
wasm-bindgen ../target/wasm32-unknown-unknown/release/double_blind_web.wasm --out-dir pkg --target web

