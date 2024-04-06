import os
import requests
import json
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Dump block JSONs for a given batch.')
parser.add_argument('batch_id', type=int, help='The batch ID to process')
args = parser.parse_args()

# Define the URLs for the RPC calls
chunks_url = 'http://34.222.160.221:8560/api/chunks?batch_index={}'.format(args.batch_id)
block_trace_url = 'http://35.93.54.141:8545'
block_trace_url = 'http://18.236.206.203:9999'

# Create the directory for the batch
batch_dir = os.path.join(os.getcwd(), 'batch_{}'.format(args.batch_id))
os.makedirs(batch_dir, exist_ok=True)

def download_chunk(chunk_id, start_block, end_block):
    # Create the directory for the chunk
    chunk_dir = os.path.join(batch_dir, 'chunk_{}'.format(chunk_id))
    os.makedirs(chunk_dir, exist_ok=True)

    # Process each block in the chunk
    for block_number in range(start_block, end_block + 1):
        # Convert the block number to hex
        hex_block_number = hex(block_number)

        # Make the request to get the block trace
        payload = {
            'jsonrpc': '2.0',
            'method': 'scroll_getBlockTraceByNumberOrHash',
            'params': [hex_block_number],
            'id': 99
        }
        response = requests.post(block_trace_url, json=payload, headers={'Content-Type': 'application/json', 'Accept-Encoding': 'gzip'})
        block_data = response.json()

        # Save the block JSON to a file
        block_file = os.path.join(chunk_dir, 'block_{}.json'.format(block_number))
        with open(block_file, 'w') as f:
            json.dump(block_data, f, indent=2)

        print('Saved block {} to {}'.format(block_number, block_file))

def download_batch():
    # Make the request to get the chunk information
    response = requests.get(chunks_url)
    chunks_data = response.json()

    # Process each chunk
    for chunk in chunks_data['chunks']:
        chunk_id = chunk['index']
        start_block = chunk['start_block_number']
        end_block = chunk['end_block_number']
        download_chunk(chunk_id, start_block, end_block)

if __name__ == "__main__":
    #download_batch()
    download_chunk(1, 1, 4)
