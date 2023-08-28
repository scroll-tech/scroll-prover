#!/bin/bash

set -ue
command -v curl &> /dev/null

# Check if the environment variable COORDINATOR_API_URL is set
if [ -z "${COORDINATOR_API_URL:-}" ]; then
  echo "COORDINATOR_API_URL is not set!"
  exit 1
fi

function exit_trap {
  reason="unknown_error"
  if [ $1 -eq 17 ]; then
    reason="runtime_error, batch_stuck"
  elif [ $1 -eq 13 ]; then
    # wrong runtime
    reason=runtime_error
  elif [ $1 -eq 1 ]; then
    # unexpected quit
    reason="unexpected_error, batch_stuck"
  elif [ $1 -eq 0 ]; then
    return
  fi

  if [ -z "${SCRIPT_ERROR:-}" ]; then
    reason="${reason}, script error"
  fi
  curl -s ${COORDINATOR_API_URL}nodewarning?panic=${reason}
}

trap "SCRIPT_ERROR=1" ERR
trap 'exit_trap $?' EXIT
trap "curl -s ${COORDINATOR_API_URL}nodewarning?panic=user_interrupt" SIGINT

if [ -z "${TESTNET_TASKS:-}" ]; then
  echo "should specify at least one tasks from mock, prove and agg, or combine them with commas"
  exit 1
fi

output_dir="${OUTPUT_DIR:-output}" 

if [ ! -d "$output_dir" ]; then
  mkdir -p "$output_dir"
  echo "Directory $output_dir created."
fi


issue_dir="${ISSUE_DIR:-issues}" 

if [ ! -d "$issue_dir" ]; then
  echo "issue dir must be created before running"
  exit 1
fi

# A function representing your command 'a'
function debug_run {
    cargo run --bin testnet-runner --release
    exit_code=$?
}

function check_output {
  set -e
  find "$output_dir" -type d | while read -r chunk_dir; do
    fail_file="${chunk_dir}/failure"

    if [ -e "$fail_file" ]; then
      #TODO copy $chunk_dir
      chunk_name=`echo "$chunk_dir" | grep -oE '[^/]+$'`
      echo "${chunk_name} fail (${chunk_dir})"
      curl -s "${COORDINATOR_API_URL}nodewarning?chunk_issue=${chunk_name}"
      mv ${chunk_dir} ${issue_dir}
    fi
  done
  set +e
}

set +e
while true; do
# clean output dir before each running
  rm -rf ${output_dir}/*
  if [ -z "${DEBUG_RUN:-}" ]; then
    testnet-runner
    exit_code=$?
  else
    debug_run
  fi
  if [ $exit_code -eq 0 ]; then
    # normal run, still sleep a while for avoiding unexpected crazy loop
    check_output
    echo "checking output done"
    sleep 10
    exit_code=$?
  elif [ $exit_code -eq 9 ]; then
    # there maybe more batchs, wait 10 min
    sleep 600
    exit_code=$?
  fi

  if [ $exit_code -ne 0 ]; then
    exit $exit_code
  fi
done