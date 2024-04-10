set -e
set -u

# The first command argument is batch-index.
batch_index=$1
if [[ ! $batch_index =~ ^[0-9]+$ ]]; then
    echo "Must specify batch-index!"
    exit
fi

# Set ENV DB_HOST, DB_USER and DB_NAME, and set password as:
# https://www.postgresql.org/docs/current/libpq-pgpass.html
db_host=$DB_HOST
db_user=$DB_USER
db_name=$DB_NAME
if [ -z $db_host ] || [ -z $db_user ] || [ -z $db_name ]; then
    echo "Must set ENV DB_HOST, DB_USER and DB_NAME!"
    exit
fi

# Replace with ENV OUTPUT_FILE.
output_file="${OUTPUT_FILE:-"full_proof_1.json"}"

# Replace with ENV CHAIN_ID.
chain_id="${CHAIN_ID:-534351}"

# Get chunk-infos.
chunk_infos=$(psql -h $db_host -U $db_user $db_name --csv -c "
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
chunk_proofs=$(psql -h $db_host -U $db_user $db_name --csv -c "
select convert_from(chunk.proof, 'UTF-8') as proofs
    from chunk join batch on chunk.batch_hash = batch.hash
    where batch.index = $batch_index
    order by chunk.index;")

chunk_proofs=$(echo $chunk_proofs | sed 's/" "/,/g')
chunk_proofs=$(echo $chunk_proofs | sed 's/""/"/g')
chunk_proofs=$(echo $chunk_proofs | sed 's/^proofs "\(.*\)"$/"chunk_proofs": [\1]/g')

echo "{$chunk_infos,$chunk_proofs}" | jq > $output_file
