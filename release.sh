IN=integration/outputs/e2e_tests_20240622_061337
OUT=release-v0.12.0

mkdir -p $OUT

# copy snark protocol and verification keys
cp $IN/chunk_chunk_0.protocol $OUT/chunk.protocol
cp $IN/batch_0.protocol $OUT/batch.protocol
cp $IN/vk_chunk_0.vkey $OUT/chunk_vk.vkey
cp $IN/vk_batch.vkey $OUT/batch_vk.vkey
cp $IN/vk_bundle.vkey $OUT/bundle_vk.key

# copy verifier contract binary
cp $IN/evm_verifier.bin $OUT/evm_verifier.bin
cp $IN/evm_verifier.yul $OUT/evm_verifier.yul

# copy public input and proof for the outermost circuit (recursive bundler)
cp $IN/pi_bundle.data $OUT/pi_data.data
cp $IN/proof_bundle.data $OUT/proof.data

# copy config values for each proving layer
cp ./integration/configs/* $OUT

cd $OUT; sha256sum * > sha256sum; cd ..

aws --profile default s3 cp $OUT s3://circuit-release/$OUT --recursive
