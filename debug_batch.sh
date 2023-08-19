rm agg-prove.log
# export MOCK_PROVE=true
export OUTPUT_DIR="batch-test"
export RUST_BACKTRACE=full
export RUST_LOG=trace
make test-agg-prove 2>&1 | tee agg-prove.log 
