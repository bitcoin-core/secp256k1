#!/bin/bash
set -e

mkdir -p build

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

run_build() {
  local config="$1"
  local flags="-O3 -mavx -mavx2 $2"
  local dir="build/$config"
  local log="${config}_build.log"
  
  mkdir -p "$dir"
  
  if (cd "$dir" && cmake ../.. -G Ninja -DCMAKE_BUILD_TYPE=Release -DSECP256K1_APPEND_CFLAGS="$flags" >"../../$log" 2>&1 && ninja >>"../../$log" 2>&1); then
    echo -e "${GREEN}✔ $config${NC}"
  else
    echo -e "${RED}✖ $config failed${NC}"
    return 1
  fi
}

run_build "BASELINE"    "-U__AVX__ -U__AVX2__"
run_build "CUSTOM_SIMD" "-D__AVX__ -D__AVX2__"

echo -e "\n${YELLOW}All builds done. Logs in project root${NC}"