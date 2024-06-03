import os
import requests
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the number of parallel downloads
MAX_PARALLEL_DOWNLOADS = 4

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Dump block JSONs for a given batch.')
parser.add_argument('batch_id', type=int, help='The batch ID to process')
parser.add_argument('chunk_id', type=int, default=0, help='The chunk ID to process')
args = parser.parse_args()

# Define the URLs for the RPC calls
chunks_url = 'http://10.6.13.141:8560/api/chunks?batch_index={}'.format(args.batch_id)
block_trace_url = 'http://10.6.13.145:8545'

# env2
chunks_url = 'http://10.6.11.134:8560/api/chunks?batch_index={}'.format(args.batch_id)
block_trace_url = 'http://10.6.11.134:8545'


# Create the directory for the batch
batch_dir = os.path.join(os.getcwd(), 'extra_traces', 'batch_{}'.format(args.batch_id))
os.makedirs(batch_dir, exist_ok=True)

def download_chunk(chunk_id, start_block, end_block):
    # Create the directory for the chunk
    chunk_dir = os.path.join(batch_dir, 'chunk_{}'.format(chunk_id))
    os.makedirs(chunk_dir, exist_ok=True)

    # Process each block in the chunk
    for block_number in range(start_block, end_block + 1):
        # Convert the block number to hex
        hex_block_number = hex(block_number)

        # Define the block file path
        block_file = os.path.join(chunk_dir, 'block_{}.json'.format(block_number))

        # Check if the file already exists and is not of size 0
        if os.path.exists(block_file) and os.path.getsize(block_file) > 0:
            print('Block {} already exists. Skipping download.'.format(block_number))
            continue

        # Make the request to get the block trace
        payload = {
            'jsonrpc': '2.0',
            'method': 'scroll_getBlockTraceByNumberOrHash',
            'params': [hex_block_number],
            'id': 99
        }
        response = requests.post(block_trace_url, json=payload, headers={'Content-Type': 'application/json', 'Accept-Encoding': 'gzip'})
        block_data = response.json()["result"]

        # Save the block JSON to a file
        with open(block_file, 'w') as f:
            json.dump(block_data, f, indent=2)

        print('Saved block {} to {}'.format(block_number, block_file))

def download_batch():
    # Make the request to get the chunk information
    response = requests.get(chunks_url)
    chunks_data = response.json()

    # Create a thread pool for parallel downloads
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_DOWNLOADS) as executor:
        futures = []
        # Submit each chunk download task to the thread pool
        for chunk in chunks_data['chunks']:
            chunk_id = chunk['index']
            if args.chunk_id != 0 and chunk_id != args.chunk_id:
                print("skip chunk", chunk_id)
                continue
            start_block = chunk['start_block_number']
            end_block = chunk['end_block_number']
            futures.append(executor.submit(download_chunk, chunk_id, start_block, end_block))
        
        # Wait for all futures to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f'Chunk download generated an exception: {exc}')


if __name__ == "__main__":
    download_batch()
    #download_chunk(1, 1, 4)
