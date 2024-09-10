set -x
blk=$1
curl -s -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"scroll_getBlockTraceByNumberOrHash", "params": ["'$(printf '0x%x' $blk)'", {"StorageProofFormat": "flatten"}], "id": 99}' 127.0.0.1:8545 | jq .result >/tmp/${blk}.json
#curl -s -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"scroll_getTxByTxBlockTrace", "params": ["'$(printf '0x%x' $blk)'", null], "id": 99}' 127.0.0.1:8545 | jq .result >/tmp/${blk}.json
