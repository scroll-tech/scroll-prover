rm agg-prove.log
# export MOCK_PROVE=true
export CHAIN_ID=53077
export OUTPUT_DIR="4-chunks-test"
export RUST_BACKTRACE=full
export RUST_LOG=trace
nohup make test-agg-prove > agg-prove.log 2>&1 &
sleep 1
tail -f agg-prove.log
