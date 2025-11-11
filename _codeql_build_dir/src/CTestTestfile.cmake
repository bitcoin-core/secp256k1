# CMake generated Testfile for 
# Source directory: /home/runner/work/secp256k1/secp256k1/src
# Build directory: /home/runner/work/secp256k1/secp256k1/_codeql_build_dir/src
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[secp256k1_noverify_tests]=] "/home/runner/work/secp256k1/secp256k1/_codeql_build_dir/bin/noverify_tests")
set_tests_properties([=[secp256k1_noverify_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;150;add_test;/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;0;")
add_test([=[secp256k1_tests]=] "/home/runner/work/secp256k1/secp256k1/_codeql_build_dir/bin/tests")
set_tests_properties([=[secp256k1_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;155;add_test;/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;0;")
add_test([=[secp256k1_exhaustive_tests]=] "/home/runner/work/secp256k1/secp256k1/_codeql_build_dir/bin/exhaustive_tests")
set_tests_properties([=[secp256k1_exhaustive_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;165;add_test;/home/runner/work/secp256k1/secp256k1/src/CMakeLists.txt;0;")
