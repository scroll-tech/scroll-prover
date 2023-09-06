set -x
set -e

# Set degree to env AGG_DEGREE, first input or default value 25.
degree="${AGG_DEGREE:-${1:-25}}"

# Set the output dir to second input or default as `./prover/test_params`.
params_dir="${2:-"./prover/test_params"}"
mkdir -p "$params_dir"

output_file="$params_dir"/params"${degree}"
rm -f "$output_file"

# degree 1 - 26
axel -ac https://circuit-release.s3.us-west-2.amazonaws.com/setup/params"$degree" -o "$output_file"
