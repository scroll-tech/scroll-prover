# ~/zip-traces/traces/304467.zip/traces-data/1095928.json
#for d in `ls ~/zip-traces/traces/`
set -x
#set -e 
set -u
#set -o pipefail
for d in `ls ~/zip-traces/0214/traces/`
do
	RUST_LOG=debug TRACE_PATH=`realpath ~/zip-traces/0214/traces/${d}/traces-data/` make mock-debug 2>&1 | tee /tmp/mock_${d}.log
exit 0 
	#RUST_LOG=debug TRACE_PATH=`realpath ~/zip-traces/0214/traces/${d}/traces-data/` make mock 2>&1 | tee /tmp/mock_${d}.log
done
