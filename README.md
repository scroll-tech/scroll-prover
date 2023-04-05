# 📜 scroll-zkevm 📜
[![Unit Test](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml/badge.svg)](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml)
![issues](https://img.shields.io/github/issues/scroll-tech/scroll-zkevm)

Scroll common rust crates.

## Usage

### Libraries
Import as an dependency to use.

### Binaries

Setup 
```shell
cargo build --release --bin setup   

./target/release/setup --params <params-file-path> --seed <seed-file-path>
```

If you run into linking issues during setup you may need to run
```shell
cp `find ./target/release/ | grep libzktrie.so` /usr/local/lib/
```
to move the zktrielib into a path where your linker can locate it

Prove
```shell
cargo build --release --bin prove

./target/release/prove --help
```

## Test
By default, prover tests are disabled due to heavy computations, if you want to run the prover tests, please run:
```
RUST_LOG=info cargo test --features prove_verify --release 
```

By default, it run the test for a trace corresponding to a block containing multiple erc20 txs. You can config `mode` ENV to test other trace:

+ `MODE=single` for a block containing 1 erc20 tx.
+ `MODE=native` for a block containing 1 native ETH transfer tx.
+ `MODE=greeter` for a block containing 1 `Greeter` contract `set_value` call tx.
+ `MODE=empty` for an empty block.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
