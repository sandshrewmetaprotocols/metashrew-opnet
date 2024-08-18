# metashrew-opnet

Rust implementation of OP_NET metaprotocol using wasmi.

## Build

```sh
cargo build --target wasm32-unknown-unknown
```

## Run

Sync a Bitcoin node, start up keydb, then, assuming your RPC port is routable via `http://localhost:8332` and Bitcoin data directory is `~/.bitcoin`:

```sh
git clone https://github.com/sandshrewmetaprotocols/metashrew
cargo build --release
./metashrew/target/release/metashrew-keydb --daemon-rpc-url http://localhost:8332 --auth $(cat ~/.bitcoin/.cookie) --indexer ./metashrew-opnet/target/wasm32-unknown-unknown/debug/metashrew-opnet.wasm --redis redis+unix:///home/ubuntu/keydb/keydb.sock
```

## Launch RPC

```sh
./metashrew/target/release/metashrew-keydb-view --redis redis+unix:///home/ubuntu/keydb/keydb.sock --indexer ./metashrew-opnet/target/wasm32-unknown-unknown/debug/metashrew-opnet.wasm
```

## Author

flex
