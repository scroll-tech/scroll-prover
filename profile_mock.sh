export CARGO_PROFILE_RELEASE_DEBUG=true

nohup make mock > mock.out 2>&1 &
echo "Mock started"

sleep 5

nohup flamegraph -o scoll-zkevm.svg --pid $(pgrep -f "integration-.* test_mock_prove") > flamegraph.out 2>&1 &
echo "Flamegraph started"
