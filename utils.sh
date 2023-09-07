set -x
set -u
#set -e
set -o pipefail

export RUST_LOG=debug
#export RUST_LOG=trace

function simple_tests() {
	for mode in sushi multiple #nft dao native empty pack
	do
		#MODE=$mode make mock 2>&1 | tee /tmp/mock_${mode}.log
		(MODE=$mode make mock > /tmp/mock_${mode}.log 2>&1) &
	done
	wait
	echo test done
	grep 'proved' /tmp/mock_*.log
}

function replace_zkevm_circuits_branch() {
	TO='tag = "v0.8.1"'
	FROM='branch = "feat/max_snark=16"'
	#FROM='branch = "refactor/partial-db"'
	sed -i "s#zkevm-circuits.git\", $FROM#zkevm-circuits.git\", $TO#" */Cargo.toml
	cargo update -p zkevm-circuits
	cargo update -p eth-types
	#git diff */Cargo.toml Cargo.lock
}

replace_zkevm_circuits_branch
#simple_tests
