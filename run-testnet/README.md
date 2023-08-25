## How is it work ##

### The runner ###

The runner (build by cargo --bin testnet-runner) acquire a batch from coordinator and handle each chunk in it.

The actions on chunks can be specified by `TESTNET_TASKS`: `mock`, `prove`, 
can also specfiy `agg` for batch level operations 

For each chunks, it create a directory naming by chunk id under `OUTPUT_DIR`, traces for this chunk is stored in a package `trace.tar.gz`
and actions from prover is traced with verbose logging (in `DEBUG` level)

If actions failed for some reason, runner would try to catch it and record a `failure` file under the chunk dir.
This include panics raised in prover. In common, runner would not exit suddendly, it exit with special exitcodes when encountering
errors it can not handle.

Env:
+ TESTNET_TASKS: specify which task should be run: `mock`, `prove`, `agg`
+ OUTPUT_DIR: the output dir, default is `output`
+ COORDINATOR_API_URL: `http://<host>/api/` (notice the ending slash '/' is important)

Runner exits:

+ 9: no more batch avaliable
+ 13: unexpected error in run-time, can not continue executing runner until the issue has been resolved.
+ 17: same as `13` but a batch task may hold without dropping from coordinator, we should reset the task manually 

### The script ###

The running script `run.sh` kept launching another runner when one has completed without error. It only exit when some serious errors
raised and nothing can be done to resume by itself. Operator should inspect the problem manually and re-run the script after that. 
When script quits it is not expected to simply restart it and hope the issue disappear automatically.

### The coordinator ###

Coordinator is a singleton service. It assigns and proxies the chunks data from proposer for mutiple runners and record the
completetion. The progress is sent to slack channel. It also relay messages from runner node to slack.

## Known issues ##

+ If runner can not access coordinator temporarily, a batch may be 'stuck' by this runner and can not be handled until operator
reset it (i.e. send a `drop` request to coordinator manually). This status would be notified to slack channel.

+ There is no data persistent avaliable for coordinator and restarting it cause losing all tasks it has currently assigned. Operator
can only adjust the least starting batch index in configuration and start assigning new task from it.

+ Currently the message from runner is proxied by coordinator and the single point failure may cause lost of node messages. We can
launch a mutiple coordinator groups dedicating for node message relaying (but still need a single instance for assigning and maintaining
tasks)

+ Any network outrage cause runner can not access l2geth would cause runner stop its handling of current batch and lost remarkable
efforts (for mock proving, it is expected to the works for about 1 hrs)


## Docker ##

+ build `Dockerfile.run_testnet` in parent directory
+ docker run -e L2GETH_API_URL=\<geth entrypoint\> -e COORDINATOR_API_URL=\<coordinator url\> -e TESTNET_TASKS=mock,prove,agg \<docker image\>
+ The entrypoint for `L2GETH_API_URL` is the URL which we passed to `geth connect`