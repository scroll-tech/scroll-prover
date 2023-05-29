set -x
set -e
set -u
set -o pipefail

export OPT_MEM=true
#export MOCK_PROVE=true
export RUST_MIN_STACK=100000000

function run_goerli_tests() {
	#MOCK_PROVE=true RUST_LOG=debug TRACE_PATH=$(realpath tests/extra_traces/hash_precompile_1.json) cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/precompile_fail.log
	RUST_LOG=debug MODE=multi cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/multi.log
	#RUST_LOG=debug MODE=sushi cargo test --features prove_verify --release test_aggregation_api -- --nocapture 2>&1 | tee logs/sushi.log
}

function run_devnet_tests() {
	CHAIN_ID=5343532222 RUST_LOG=debug TRACE_PATH=$(realpath tests/extra_traces/devnet.json) cargo test --features prove_verify --release test_agg -- --nocapture 2>&1 | tee logs/devnet.log
}


function upload_release_files_testnet() {
	VERSION="v0.3.1-testnet"
	TRACE=tests/extra_traces/devnet.json
	CHAIN_ID=`jq .result.chainID $TRACE`
	OUTPUT=output_20230528_162421_multi
	RELEASE_DIR=release_files/release-${VERSION}
	mkdir -p $RELEASE_DIR 
	for f in full_proof.data  verifier.sol verify_circuit.vkey
	do 
		cp $OUTPUT/$f $RELEASE_DIR
	done
	cp $TRACE $RELEASE_DIR/trace.json
	find $RELEASE_DIR -type f | xargs sha256sum > /tmp/sha256sum
	mv /tmp/sha256sum $RELEASE_DIR/sha256sum
	aws  --profile default s3 cp $RELEASE_DIR s3://circuit-release/circuit-release/release-${VERSION} --recursive
	aws  --profile default s3 ls s3://circuit-release/circuit-release/release-${VERSION}/
}
function upload_release_files_goerli() {
	VERSION="v0.3.1"
	TRACE=./tests/traces/erc20/multiple.json
	CHAIN_ID=`jq .result.chainID $TRACE`
	OUTPUT=output_20230528_162421_multi
	RELEASE_DIR=release_files/release-${VERSION}
	mkdir -p $RELEASE_DIR 
	for f in full_proof.data  verifier.sol verify_circuit.vkey
	do 
		cp $OUTPUT/$f $RELEASE_DIR
	done
	cp $TRACE $RELEASE_DIR/trace.json
	find $RELEASE_DIR -type f | xargs sha256sum > /tmp/sha256sum
	mv /tmp/sha256sum $RELEASE_DIR/sha256sum
	aws  --profile default s3 cp $RELEASE_DIR s3://circuit-release/circuit-release/release-${VERSION} --recursive
	aws  --profile default s3 ls s3://circuit-release/circuit-release/release-${VERSION}/
}

upload_release_files_goerli	
upload_release_files_testnet

#run_goerli_tests
#run_devnet_tests
