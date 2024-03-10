CURRENTDATE := $(shell date +"%Y-%m-%d")

.PHONY: help test-ci test-all build-release fmt clippy test bridge-test mock mock-debug mock-testnet test-inner-prove test-chunk-prove test-agg-prove test-batch-prove test-batches-with-each-chunk-num-prove test-ccc rows download-setup

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

bridge-test:
	cargo build --release
	./target/release/prove --params=./test_params --trace=prover/tests/traces/bridge

mock: ## Run mock test
	@cargo test --features prove_verify --release test_mock_prove -- --exact --nocapture

mock-debug: ## Run mock test with debug
	@cargo test --features prove_verify test_mock_prove -- --exact --nocapture

mock-testnet: ## Run mock testnet
	@cargo run --bin mock_testnet --release

test-inner-prove: ## Run inner prove verification test
	@cargo test --features prove_verify --release test_inner_prove_verify

test-chunk-prove: ## Run chunk prove verification test
	@cargo test --features prove_verify --release test_chunk_prove_verify

test-agg-prove: ## Run aggregate prove verification test
	@cargo test --features prove_verify --release test_agg_prove_verify

test-batch-prove: ## Run batch prove verification test
	@cargo test --features prove_verify --release test_batch_prove_verify

test-batches-with-each-chunk-num-prove: ## Run batches with each chunk num prove verification test
	@cargo test --features prove_verify --release test_batches_with_each_chunk_num_prove_verify

test-ccc: ## Run capacity checker test
	@cargo test --release test_capacity_checker

rows: ## Estimate circuit rows
	@cargo test --features prove_verify --release estimate_circuit_rows

download-setup: ## Download setup
	sh download_setup.sh ${degree} ${params_dir}

.PHONY: help fmt clippy test test-ci test-all
	
