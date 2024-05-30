CURRENTDATE=`date +"%Y-%m-%d"`

CHAIN_ID ?= 534352
export CHAIN_ID
RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test-ci: fmt clippy test ## Run all the CI checks locally (in your actual toolchain)

test-all: test-ci ## Run all available tests

build-release: ## Check build in release mode
	@cargo build --release

fmt: ## Check whether the code is formatted correctly
	@cargo check --all-features

clippy: ## Run clippy checks over all workspace members
	@cargo check --all-features
	@cargo clippy --all-features --all-targets -- -D warnings

test: ## Run tests for all the workspace members
	@cargo test --release -p integration --test unit_tests

mock:
	@cargo test --features prove_verify --release test_mock_prove -- --exact --nocapture

mock-debug:
	@cargo test --features prove_verify test_mock_prove -- --exact --nocapture

mock-testnet:
	@cargo run --bin mock_testnet --release

test-inner-prove:
	@cargo test --features prove_verify --release test_inner_prove_verify

test-chunk-prove:
	@cargo test --features prove_verify --release test_chunk_prove_verify

test-agg-prove:
	@cargo test --features prove_verify --release test_agg_prove_verify

test-pi:
	@cargo test --features prove_verify --release test_batch_pi

test-batch-prove:
	@cargo test --features prove_verify --release test_batch_prove_verify

test-batches-with-each-chunk-num-prove:
	@cargo test --features prove_verify --release test_batches_with_each_chunk_num_prove_verify

test-ccc:
	@cargo test --release test_capacity_checker

rows:
	@cargo test --features prove_verify --release estimate_circuit_rows

# Could be called as `make download-setup -e degree=DEGREE params_dir=PARAMS_DIR`.
# As default `degree=25` and `params_dir=./integration/params`.
download-setup:
	sh download_setup.sh ${degree} ${params_dir}

.PHONY: help fmt clippy test test-ci test-all
