set -x
set -u
#set -e
set -o pipefail

export KECCAK_ROWS=20
export RUST_LOG=trace

function check_batch() {
	TRACE_VER="0228-alpha"
#	for d in $(ls ~/zip-traces/${TRACE_VER}/traces/); do
d="2618.zip"
		TRACE_PATH=$(realpath ~/zip-traces/${TRACE_VER}/traces/${d}/traces-data/) make mock 2>&1 | tee /tmp/mock_${d}.log
#	done
}

function check_block() {
	TRACE_VER=0218
	for t in $(ls ~/zip-traces/${TRACE_VER}); do
		TRACE_PATH=$(realpath ~/zip-traces/${TRACE_VER}/${t}) make mock 2>&1 | tee /tmp/mock_${t}.log
	done
}

check_batch
