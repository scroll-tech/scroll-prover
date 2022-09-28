set -x
block=$1
out=/tmp/${block}.json
curl --location --request POST 'https://prealpha.scroll.io/l2' --header 'Content-Type: application/json' --data-raw '{"jsonrpc": "2.0","method": "scroll_getBlockResultByNumberOrHash","params":["'`printf '0x%x' $block`'"],"id": 1}' | python3 -m json.tool > $out
echo download to $out
du -sh $out
