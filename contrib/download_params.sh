#!/bin/bash
set -uex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
PROJ_DIR=$DIR"/.."

pushd $PROJ_DIR
mkdir -p test_params
RELEASE_VERSION=release-0920
wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/test_seed -O test_seed
wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/test_params/params18 -O ./test_params/params18
wget https://circuit-release.s3.us-west-2.amazonaws.com/circuit-release/$RELEASE_VERSION/test_params/params25 -O ./test_params/params25
popd
