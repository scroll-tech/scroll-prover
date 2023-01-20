set -x
set -e

export OPT_MEM=true
#export MOCK_PROVE=true
export KECCAK_ROWS=28
export RUST_MIN_STACK=100000000

function mock() {
	cd ..
	make mock 2>&1 | tee mock.log
	make mock_pack 2>&1 | tee mock_pack.log
	cd zkevm
}

function soli() {
	RUST_LOG=info EXP=output_20221014_134235_multi cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.soli
}

function step0() {
	RUST_LOG=debug PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=PACK cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.pack
	#RUST_LOG=debug GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=greeter cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.greeter
#	RUST_LOG=debug GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=greeter cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.greeter
}

function check_same() {
	RUST_LOG=info PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=multi cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.multi1
	#RUST_LOG=debug GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=multi cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.multi2
}
function step1() {
	RUST_LOG=info GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=multi cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.multi
	RUST_LOG=debug GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=dao cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.dao
	#RUST_LOG=info GEN_SOLI=true PARAM_SEED=bb4b94a1bbef58c4b5fcda6c900629b5 MODE=sushi cargo test --features prove_verify --release test_4in1 -- --nocapture 2>&1 | tee logs/4in1.log.sushi
}


step1

