set -x
set -e
set -o pipefail

export OPT_MEM=true
#export MOCK_PROVE=true
#export KECCAK_ROWS=28
export RUST_MIN_STACK=100000000
export PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 

function run_agg_tests() {
	#RUST_LOG=info MODE=single cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/4in1.log.single
	RUST_LOG=debug MODE=multi cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/4in1.log.multi
	RUST_LOG=info MODE=sushi cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/4in1.log.sushi
	#RUST_LOG=trace PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=native cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/4in1.log.native
}

run_agg_tests

