echo 'processing '$PROVE_BEGIN_BATCH to $PROVE_END_BATCH
mock_testnet > /opt/test_logs/$PROVE_BEGIN_BATCH-$PROVE_END_BATCH.log 2>&1
