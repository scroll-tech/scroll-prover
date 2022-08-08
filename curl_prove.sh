#!/bin/bash

# Must install jq on server. (e.g. sudo apt-get install jq)
# sudo apt-get install jq -y
# sudo yum install jq -y
curl https://rollupscanapi.scroll.io/api/l2_blocks?per_page=1000 | jq .blocks > l2_blocks.json
hashes=`jq [.[].header_hash] < ./l2_blocks.json`

mkdir -p all_traces

for i in "${!hashes[@]}";
do
	echo "-------- Downloading $i ${hashes[$i]}"
	curl --location --request POST 'https://prealpha.scroll.io/l2' \
	--header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0","method": "eth_getBlockResultByHash","params":["${hashes[$i]}"],"id": 1}' > ./all_traces/${i}.trace
	echo "-------- Proving $i ${hashes[$i]}"
	./target/release/prove --agg ./all_traces/${i}.proof --params zkevm/test_params --seed zkevm/test_seed
done

