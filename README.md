# scroll-common
[![Unit Test](https://github.com/scroll-tech/common-rs/actions/workflows/unit_test.yml/badge.svg)](https://github.com/scroll-tech/common-rs/actions/workflows/unit_test.yml)
![issues](https://img.shields.io/github/issues/scroll-tech/common-rs)

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

Prove
```shell
cargo build --release --bin prove

./target/release/prove --params zkevm/test_params --seed zkevm/test_seed --trace zkevm/tests/erc20/multiple.json --evm evm_proof_multiple-erc20 --state state_proof_multiple-erc20
```

## Test
By default, prover tests are disabled due to heavy computations, if you want to run the prover test, please run:
```
RUST_LOG=info cargo test --features prove_verify --release test_evm_prove_verify
```

or
```
RUST_LOG=info cargo test --features prove_verify --release test_state_prove_verify
```

(Please don't run `test_evm_prove_verify` and `test_state_prove_verify` concurrently.)

By default, it run the test for a trace corresponding to a block containing multiple erc20 txs. You can config `mode` ENV to test other trace:

+ `MODE=single` for a block containing 1 erc20 tx.
+ `MODE=native` for a block containing 1 native ETH transfer tx.
+ `MODE=greeter` for a block containing 1 `Greeter` contract `set_value` call tx.
+ `MODE=empty` for an empty block.
