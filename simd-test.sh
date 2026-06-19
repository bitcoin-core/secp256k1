#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

run_test() {
  local config="$1"
  local dir="build/$config"
  local log="${config}_test.log"

  if [[ ! -d "$dir" ]]; then
    echo -e "${RED}✖ $config${NC} (no dir)"
    return 1
  fi

  if (cd "$dir" && ctest --output-on-failure -j"$(nproc)" &> "../../$log"); then
    echo -e "${GREEN}✔ $config${NC} (log: $log)"
  else
    echo -e "${RED}✖ $config${NC} (log: $log)"
    return 1
  fi
}

run_test "BASELINE"
run_test "CUSTOM_SIMD"

echo -e "\n${YELLOW}All tests passed. Logs in project root${NC}"