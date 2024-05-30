set -e
set -u

# The first command argument is batch-index.
batch_index=$1
if [[ ! $batch_index =~ ^[0-9]+$ ]]; then
    echo "Must specify batch-index!"
    exit
fi

# psql -h $db_host -p $db_port -U $db_user $db_name
db_conn=""

# Replace with ENV OUTPUT_FILE.
output_file="${OUTPUT_FILE:-"batch_task.json"}"

# Replace with ENV CHAIN_ID.
chain_id="${CHAIN_ID:-534351}"

# Get chunk-infos.
chunk_infos=$($db_conn --csv -c "
select json_agg(res) as infos from (
    select
        $chain_id as chain_id,
        false as is_padding,
        chunk.state_root              as post_state_root,
        chunk.parent_chunk_state_root as prev_state_root,
        chunk.withdraw_root           as withdraw_root,
        chunk.hash                    as data_hash
    from chunk join batch on chunk.batch_hash = batch.hash
    where batch.index = $batch_index
    order by chunk.index
) res;")

chunk_infos=$(echo $chunk_infos | sed 's/""/"/g')
chunk_infos=$(echo $chunk_infos | sed 's/^infos "\(.*\)"$/"chunk_infos": \1/g')

# Get chunk-proofs.
chunk_proofs=$($db_conn --csv -c "
select convert_from(chunk.proof, 'UTF-8') as proofs
    from chunk join batch on chunk.batch_hash = batch.hash
    where batch.index = $batch_index
    order by chunk.index;")

chunk_proofs=$(echo $chunk_proofs | sed 's/" "/,/g')
chunk_proofs=$(echo $chunk_proofs | sed 's/""/"/g')
chunk_proofs=$(echo $chunk_proofs | sed 's/^proofs "\(.*\)"$/"chunk_proofs": [\1]/g')

echo "{$chunk_infos,$chunk_proofs}" | jq > $output_file
