CURRENTDATE=`date +"%Y-%m-%d"`

CHAIN_ID ?= 534352
export CHAIN_ID
RUST_MIN_STACK ?= 100000000
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
	@cargo test --release --all

mock-testnet:
	@cargo run --bin mock_testnet --release

mock:
	@cargo test --features prove_verify --release test_mock_prove -- --exact --nocapture

test-inner-prove:
	@cargo test --features prove_verify --release test_inner_prove_verify -- --exact --nocapture

test-chunk-prove:
	@cargo test --features prove_verify --release test_chunk_prove_verify -- --exact --nocapture

test-e2e-prove:
	@cargo test --features prove_verify --release test_e2e_prove_verify -- --exact --nocapture

test-batch-prove:
	@cargo test --features prove_verify --release test_batch_prove_verify -- --exact --nocapture

test-ccc:
	@cargo test --features prove_verify --release test_capacity_checker -- --exact --nocapture

rows:
	@cargo test --features prove_verify --release estimate_circuit_rows -- --exact --nocapture

# Could be called as `make download-setup -e degree=DEGREE params_dir=PARAMS_DIR`.
# As default `degree=25` and `params_dir=./prover/test_params`.
download-setup:
	sh download_setup.sh ${degree} ${params_dir}

.PHONY: help fmt clippy test test-ci test-all
