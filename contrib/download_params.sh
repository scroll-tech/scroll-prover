#!/bin/bash
set -uex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
PROJ_DIR=$DIR"/.."

pushd $PROJ_DIR
mkdir -p test_params
RELEASE_VERSION=params-0320
wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/params20 -O ./test_params/params20
wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/params26 -O ./test_params/params26
#wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/test_seed -O test_seed
#wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/verify_circuit.vkey -O agg_vk
popd
