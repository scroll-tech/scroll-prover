set -x
set -e
set -o pipefail

git_commit_id=`git rev-parse --short HEAD`

cargo build --release
find target/release | grep libzktrie.so | xargs -i cp {} ./
cp target/release/libffi.a ./libzkp.a
zip -r $git_commit_id.zip libzktrie.a libzkp.a
rm libzktrie.a libzkp.a