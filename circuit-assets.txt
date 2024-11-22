

## Circuit Setup Files

Setup files are not related to circuit versions. Available in Scroll S3 or PSE S3:

```
for degree in 20 21 24 25 26
do
  wget https://circuit-release.s3.us-west-2.amazonaws.com/setup/params${degree}
  # or 
  # wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/perpetual-powers-of-tau-raw-${degree} -O params${degree}
done
```

To know more about how these files are generated, see [here](https://github.com/han0110/halo2-kzg-srs?tab=readme-ov-file#download-the-converted-srs)


## Circuit Assets Files (VKs)


Assets files are related to circuit versions. Available in Github [latest](./release-latest) and S3:

```

VERSION="v0.13.1"
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/sha256sum
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/chunk.protocol
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/evm_verifier.bin
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/evm_verifier.yul
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer1.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer2.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer3.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer4.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer5.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/layer6.config
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/pi.data
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/preprocessed_digest.hex
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/proof.data
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/vk_batch.vkey
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/vk_bundle.vkey
wget https://circuit-release.s3.us-west-2.amazonaws.com/release-v${VERSION}/vk_chunk.vkey
```
