set -x
set -u
set -e 
set -o pipefail

export KECCAK_ROWS=20
export RUST_LOG=trace
TRACE_VER=0217
for d in `ls ~/zip-traces/${TRACE_VER}/traces/`
do
	TRACE_PATH=`realpath ~/zip-traces/${TRACE_VER}/traces/${d}/traces-data/` make mock 2>&1 | tee /tmp/mock_${d}.log
done
