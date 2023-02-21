set -x
set -e

# git_commit_id=`git rev-parse --short HEAD`

cargo build --release
find target/release | grep libzktrie.so | xargs -i cp {} ./
cp target/release/libffi.a ./libzkp.a
zip -r libs.zip libzktrie.so libzkp.a
rm libzktrie.so libzkp.a