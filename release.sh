set -x
set -e

# git_commit_id=`git rev-parse --short HEAD`

cargo build --release
find target/release | grep libzktrie.so | xargs -i cp {} ./
cp target/release/libffi.a ./libzkp.a

shasum -a 256 libzkp.a > zkp.sha256
shasum -a 256 libzktrie.so > zktrie.sha256

zip -r libs.zip libzktrie.so libzkp.a zkp.sha256 zktrie.sha256
shasum -a 256 libs.zip > zip.sha256

rm libzktrie.so libzkp.a zkp.sha256 zktrie.sha256