RUST_MIN_STACK=16777216 COINBASE=0x5300000000000000000000000000000000000005 CHAIN_ID=534352 TRACE_PATH=`realpath integration/tests/extra_traces/batch_25/chunk_113/` RUST_LOG=trace make mock 2>&1 |tee mock.log