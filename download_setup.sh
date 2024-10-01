#!/bin/sh
set -eux

# Set degree to env SCROLL_PROVER_MAX_DEGREE, first input or default value 26.
degree="${SCROLL_PROVER_MAX_DEGREE:-${1:-26}}"

# Set the output dir to second input or default as `./integration/params`.
params_dir="${2:-"./integration/params"}"
mkdir -p "$params_dir"

output_file="$params_dir"/params"${degree}"
rm -f "$output_file"

# degree 1 - 26
axel -ac https://circuit-release.s3.us-west-2.amazonaws.com/setup/params"$degree" -o "$output_file"
