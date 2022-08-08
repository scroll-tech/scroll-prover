#!/bin/bash

# Must install jq on server. (e.g. sudo apt-get install jq)
# sudo apt-get install jq -y
# sudo yum install jq -y
curl https://rollupscanapi.scroll.io/api/l2_blocks?per_page=1000 | jq .blocks > l2_blocks.json

mkdir -p all_traces

i=0
for hash in `jq .[].header_hash l2_blocks.json`;
do
	echo "-------- Downloading $i $hash --------"
	curl --location --request POST 'https://prealpha.scroll.io/l2' \
	--header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0","method": "eth_getBlockResultByHash","params":['${hash}'],"id": 1}'  > ./all_traces/${i}.trace
	echo "-------- Proving $i $hash --------"
	./target/release/prove --trace ./all_traces/${i}.trace --agg ./all_traces/${i}.proof --params zkevm/test_params --seed zkevm/test_seed
	i=$((i+1))
	if [ $i == 32 ]; then
	        break
	fi
done

