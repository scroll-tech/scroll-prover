CHAIN_ID=534352 TRACE_PATH=`realpath integration/tests/extra_traces/batch_495/chunk_495/` RUST_LOG=trace make mock 2>&1 |tee mock.log
