#!/bin/bash

set -ue
command -v curl &> /dev/null

# Check if the environment variable COORDINATOR_API_URL is set
if [ -z "${COORDINATOR_API_URL:-}" ]; then
  echo "COORDINATOR_API_URL is not set!"
  exit 1
fi

function exit_trap {
  if [ $1 -ne 0 ]; then
    curl ${COORDINATOR_API_URL}nodewarning?panic=runtime_error
  fi
}

trap "curl ${COORDINATOR_API_URL}nodewarning?panic=script_error" ERR
trap 'exit_trap $?' EXIT
trap "curl ${COORDINATOR_API_URL}nodewarning?panic=user_interrupt" SIGINT

if [ -z "${TESTNET_TASKS:-}" ]; then
  echo "should specify at least one tasks from mock, prove and agg, or combine them with commas"
  exit 1
fi

output_dir="${OUTPUT_DIR:-output}" 

if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
  echo "Directory $output_dir created."
fi

# A function representing your command 'a'
function debug_run {
    cargo run --bin testnet-runner --release
    exit_code=$?
}

function check_output {
  find "$output_dir" -type d | while read -r chunk_dir; do
    fail_file="${chunk_dir}/failure"

    if [ -e "$fail_file" ]; then
      #TODO copy $chunk_dir
      chunk_name=`echo "$chunk_dir" | grep -oE '[^/]+$'`
      echo "${chunk_name} fail (${chunk_dir})"
      curl "${COORDINATOR_API_URL}nodewarning?chunk_issue=${chunk_name}"
    fi
  done
}

while true; do
# clean output dir before each running
  rm -rf ${output_dir}/*
  set +e
  if [ -z "${DEBUG_RUN:-}"]; then
    echo "no implement!"
    exit 1  
  else
    debug_run
  fi
  set -e
  if [ $exit_code -eq 0 ]; then
    # normal run, still sleep a while for avoiding unexpected crazy loop
    check_output
    sleep 10
  elif [ $exit_code -eq 9 ]; then
    # there maybe more batchs, wait 10 min
    sleep 600
  elif [ $exit_code -eq 13 ]; then
    # wrong runtime
    exit 1
    # Perform action B
  elif [ $exit_code -eq 17 ]; then
    curl ${COORDINATOR_API_URL}nodewarning?panic=runtime_error_with_batch_stuck
    exit 1
  else
    echo "exit with unknown reason"
    exit 1
  fi
done