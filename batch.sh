set -x
set -u
set -e 
set -o pipefail

export KECCAK_ROWS=20
export RUST_LOG=trace

function check_batch() {
	TRACE_VER="0228-alpha"
	for d in $(ls ~/zip-traces/${TRACE_VER}/traces); do
		export TRACE_PATH=$(realpath ~/zip-traces/${TRACE_VER}/traces/${d}/traces-data) 
		make rows 2>&1 | tee rows.log
		(make mock 2>&1 | tee /tmp/mock_${d}.log) || (echo /tmp/mock_${d}.log; exit 1)
	done
}

function check_block() {
	TRACE_VER=0303-tencent
	for t in $(ls ~/zip-traces/${TRACE_VER}); do
		TRACE_PATH=$(realpath ~/zip-traces/${TRACE_VER}/${t}) make mock 2>&1 | tee /tmp/mock_${t}.log
	done
}

#check_block
check_batch
