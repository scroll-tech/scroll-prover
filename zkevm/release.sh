set -x
set -e
set -u
set -o pipefail

export OPT_MEM=true
#export MOCK_PROVE=true
export RUST_MIN_STACK=100000000

function run_goerli_tests() {
	MOCK_PROVE=true RUST_LOG=debug TRACE_PATH=$(realpath tests/extra_traces/hash_precompile_1.json) cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/precompile_fail.log

	#RUST_LOG=debug MODE=multi cargo test --features prove_verify --release test_aggregation_api -- --nocapture 2>&1 | tee logs/multi.log
	#RUST_LOG=debug MODE=sushi cargo test --features prove_verify --release test_aggregation_api -- --nocapture 2>&1 | tee logs/sushi.log
}

function run_devnet_tests() {
	CHAIN_ID=5343532222 RUST_LOG=debug TRACE_PATH=$(realpath tests/extra_traces/devnet.json) cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/devnet.log
}

run_goerli_tests
run_devnet_tests
