set -x
set -u
#set -e 
set -o pipefail

export RUST_LOG=trace

function check_batch() {
	TRACE_VER="0317-alpha"
	for d in $(ls ~/zip-traces/${TRACE_VER}/traces); do
		export TRACE_PATH=$(realpath ~/zip-traces/${TRACE_VER}/traces/${d}/traces-data) 
		make mock 2>&1 | tee /tmp/mock_${d}.log
	done
}

function check_block() {
	for t in prover/tests/extra_traces/tx_storage_proof.json prover/tests/extra_traces/hash_precompile_2.json prover/tests/extra_traces/hash_precompile_1.json prover/tests/traces/sushi/sushi_chef-withdraw.json prover/tests/traces/erc20/erc20_10_transfer.json; do
		TRACE_PATH=`realpath $t` make mock 2>&1 | tee /tmp/mock_`basename $t`.log
	done
}

check_block
#check_batch
