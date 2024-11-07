export OUTPUT_DIR=`realpath integration/outputs/e2e_tests_20241107_065112`
RUST_LOG=debug make test-e2e-prove 2>&1 |tee e2e.log
