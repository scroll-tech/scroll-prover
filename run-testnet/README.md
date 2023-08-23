
Env:
+ TESTNET_TASKS: specify which task should be run: `mock`, `prove`, `agg`
+ OUTPUT_DIR: the output dir, default is `output`
+ COORDINATOR_API_URL: `http://<host>/api/` (notice the ending slash '/' is important)

App exits:

+ 9: no more batch avaliable
+ 13: unexpected error in run-time, can not continue executing runner until the issue has been resolved.
+ 17: same as `13` but a batch task may hold without dropping from coordinator, we should reset the task manually 