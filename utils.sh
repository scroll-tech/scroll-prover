set -x
set -u
#set -e
set -o pipefail

export RUST_LOG=debug
#export RUST_LOG=trace

function fetch_trace() {
	for blk in $(seq $1 $2); do
		echo download $blk
		curl -s -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"scroll_getBlockTraceByNumberOrHash", "params": ["'$(printf '0x%x' $blk)'"], "id": 99}' $RPC | python3 -m json.tool >/tmp/${blk}.json
	done
}

function simple_tests() {
	for mode in sushi multiple; do #nft dao native empty pack
		#MODE=$mode make mock 2>&1 | tee /tmp/mock_${mode}.log
		(MODE=$mode make mock >/tmp/mock_${mode}.log 2>&1) &
	done
	wait
	echo test done
	grep 'proved' /tmp/mock_*.log
}

function replace_zkevm_circuits_branch() {
	TO='tag = "v0.9.7"'
	FROM='branch = "develop"'
	#FROM='branch = "refactor/partial-db"'
	sed -i "s#zkevm-circuits.git\", $FROM#zkevm-circuits.git\", $TO#" Cargo.toml
	cargo update -p zkevm-circuits
	cargo update -p eth-types
	#git diff */Cargo.toml Cargo.lock
}

#fetch_trace $1 $2
replace_zkevm_circuits_branch
#simple_tests
