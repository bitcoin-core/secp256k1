#!/bin/bash
set -e

options=("OFF" "ON")
BENCH_ITERS=${SECP256K1_BENCH_ITERS:-20000}

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo > /dev/null
sudo cpupower -c 0 frequency-set -g performance > /dev/null
command -v taskset > /dev/null && TASKSET_CMD="taskset -c 0"

run_bench() {
  local dir=$1 bin=$2 log=$3
  (
    cd "$dir"
    $TASKSET_CMD env SECP256K1_BENCH_ITERS=$BENCH_ITERS nice -n 0 ./bin/$bin >> "../../$log" 2>&1
    echo "" >> "../../$log"
  )
}

bench_all() {
  local config="$1"
  local dir="build/$config"
  local log="${config}_bench.csv"

  if [[ ! -d "$dir" ]]; then
    echo -e "${RED}✖ $config${NC} (no dir)"
    return 1
  fi
  
  {
    echo "Benchmark results for $config"
    echo "Generated on $(date)"
    echo "Iterations: $BENCH_ITERS"
    echo ""
  } > "$log"

  for bin in bench bench_ecmult bench_internal; do
    if run_bench "$dir" "$bin" "$log"; then
      echo -e "  ${GREEN}✔ $bin${NC}"
    else
      echo -e "  ${RED}✖ $bin${NC}"
      return 1
    fi
  done

  echo -e "${GREEN}✔ $config${NC} (log: $log)"
}

bench_all "BASELINE"
bench_all "CUSTOM_SIMD"

echo -e "\n${YELLOW}All benchmarks successful. Logs in project root${NC}"