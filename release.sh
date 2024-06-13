IN=integration/outputs/e2e_tests_20240613_004538
OUT=release-v0.11.1

mkdir -p $OUT
cp $IN/chunk_chunk_0.protocol $OUT/chunk.protocol
cp $IN/vk_batch_agg.vkey $OUT/agg_vk.vkey
cp $IN/vk_chunk_0.vkey $OUT/chunk_vk.vkey
cp $IN/evm_verifier.bin $OUT/evm_verifier.bin
cp $IN/evm_verifier.yul $OUT/evm_verifier.yul
cp $IN/pi_batch_agg.data $OUT/pi_data.data
cp $IN/proof_batch_agg.data $OUT/proof.data
cp ./integration/configs/* $OUT
cd $OUT; sha256sum * > sha256sum; cd ..

aws --profile default s3 cp $OUT s3://circuit-release/$OUT --recursive
