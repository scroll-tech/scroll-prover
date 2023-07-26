set -x
set -u
#set -e
set -o pipefail

export RUST_LOG=debug
#export RUST_LOG=trace

function simple_tests() {
	for mode in pack sushi multiple nft dao native empty 
	do
		#MODE=$mode make mock 2>&1 | tee /tmp/mock_${mode}.log
		(MODE=$mode make mock > /tmp/mock_${mode}.log 2>&1) &
	done
	wait
	echo test done
	grep 'proved' /tmp/mock_*.log
}

function replace_zkevm_circuits_branch() {
	TO=feat/withdraw_proof
	FROM=develop
	sed -i 's#zkevm-circuits.git", branch = "'$FROM'#zkevm-circuits.git", branch = "'$TO'#' */Cargo.toml
	cargo update -p zkevm-circuits
	cargo update -p eth-types
	git diff */Cargo.toml Cargo.lock
}

replace_zkevm_circuits_branch
#simple_tests
