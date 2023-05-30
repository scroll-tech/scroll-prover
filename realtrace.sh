set -x
set -e
set -o pipefail

export OPT_MEM=true
#export MOCK_PROVE=true
#export KECCAK_ROWS=20
#export KECCAK_DEGREE=19
export RUST_MIN_STACK=100000000
export PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 

function realtrace() {
		d="617365.json"
		RUST_LOG=info TRACE_PATH=`realpath ./${d}` cargo test --features prove_verify --release test_aggregation_api -- --nocapture 2>&1 | tee agg.${d}.log
}

realtrace
