set -x
set -u
set -e
set -o pipefail

#export RUST_LOG=debug
export RUST_LOG=trace

function simple_tests() {
	for mode in pack #sushi multiple #nft dao native empty # pack
	#for mode in native empty # pack
	do
		MODE=$mode make mock 2>&1 | tee /tmp/mock_${mode}.log
	done
}

function replace_zkevm_circuits_branch() {
	BRANCH=feat/deploy_at_existed_acc
	sed -i 's#zkevm-circuits.git", branch = "develop#zkevm-circuits.git", branch = "'$BRANCH'#' */Cargo.toml
	git diff */Cargo.toml
}

#replace_zkevm_circuits_branch
simple_tests
