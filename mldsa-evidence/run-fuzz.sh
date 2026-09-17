#!/bin/bash
BASE="${BASE:-$(cd "$(dirname "$0")" && pwd)/work}"
set -e
for s in 2 3 4; do
  d=${BASE}/fuzz-out/seed$s; mkdir -p $d; cp ${BASE}/fuzz-out/pool.bin $d/
  ${BASE}/target-diff/release/fuzz $d 10000000 $s 60 > $d/fuzz118.txt 2> $d/fuzz118.err
  ${BASE}/target-diff116/release/mldsa-diff116 $d 10000000 $s 60 > $d/fuzz116.txt 2> $d/fuzz116.err
done
echo ALLDONE
