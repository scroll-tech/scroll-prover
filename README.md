# 📜 scroll-zkevm 📜
[![Unit Test](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml/badge.svg)](https://github.com/scroll-tech/scroll-zkevm/actions/workflows/unit_test.yml)
![issues](https://img.shields.io/github/issues/scroll-tech/scroll-zkevm)

## Usage


### Testing

`make test-agg` is the main testing entry point for the multi-level circuit constraint system of scroll-zkevm. Developers can understand how the system works by reading the codes of this test.

Besides, `make test-super-trace` can be used to test the first-level circuit.

### Binaries

This repository is designed to be used as a Rust crate, rather than a standalone running process. However, you can still use the following command to run binaries locally.

Setup 
```shell
cargo build --release --bin setup

./target/release/setup --params <params-file-path>
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

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
