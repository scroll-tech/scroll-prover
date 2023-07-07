# 📜 scroll-zkevm 📜
[![Unit Test](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml/badge.svg)](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml)
![issues](https://img.shields.io/github/issues/scroll-tech/scroll-zkevm)

## Usage

### Prerequisite

Fetch git-submodule of test traces
```shell
git submodule init
git submodule update --checkout
```

Download all setup params, degree `20` and `25` are used in [config.rs](https://github.com/scroll-tech/scroll-prover/tree/main/prover/src/config.rs).
Could only download params of degree `25`, but it may affect performance (when dowsizing to `20`).
```shell
make download-setup -e degree=20
make download-setup -e degree=25
```
Or specify other degree and target directory to download.
```shell
# As default `degree=25` and `params_dir=./prover/test_params`.
make download-setup -e degree=DEGREE params_dir=PARAMS_DIR
```

### Testing

`make test-chunk-prove` and `make test-agg-prove` are the main testing entries for multi-level circuit constraint system of scroll-prover. Developers could understand how the system works by reading the codes of these tests.

Besides it, `make test-inner-prove` could be used to test the first-level circuit, and `make-comp-prove` could be used to test two-layers compression circuits.

### Binaries

This repository is designed to be used as a Rust crate, rather than a standalone running process. However, you can still use the following command to run binaries locally.

If you run into linking issues you may need to run
```shell
cp `find ./target/release/ | grep libzktrie.so` /usr/local/lib/
```
To move the zktrielib into a path where your linker could locate it.

Run prover
```shell
cargo build --release --bin prove

./target/release/prove --help
```
Could specify arguments as
```shell
cargo run --release --bin prove -- --params=./prover/test_params --trace=./prover/tests/traces/erc20/10_transfer.json
```

Run verifier
```shell
cargo build --release --bin verify

./target/release/verify --help
```
Could specify arguments as
```shell
cargo run --release --bin verify -- --params=./prover/test_params --vk=./proof_data/chunk.vkey
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
