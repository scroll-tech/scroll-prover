set -x
set -e

# Set degree to env AGG_DEGREE, first input or default value 25.
degree="${AGG_DEGREE:-${1:-25}}"

# Set the output dir to second input or default as `./zkevm/test_params`.
params_dir="${2:-"./zkevm/test_params"}"
mkdir -p "$params_dir"

output_file="$params_dir"/params"${degree}"
rm -f "$output_file"

axel -ac https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/perpetual-powers-of-tau-raw-"$degree" -o "$output_file"
