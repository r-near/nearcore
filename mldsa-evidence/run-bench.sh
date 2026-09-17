#!/bin/bash
BASE="${BASE:-$(cd "$(dirname "$0")" && pwd)/work}"
# Interleaved ML-DSA-65 benchmark: every round runs each (impl, op) once in shuffled order,
# as a separate process pinned to one core.
B=${BASE}/target-bench/release/bench
B116=${BASE}/target-bench116/release/bench116
OUT=${BASE}/bench-out/raw.txt
CORE=${CORE:-6}
ROUNDS=${ROUNDS:-21}
mkdir -p ${BASE}/bench-out; : > $OUT
echo "start $(date -Is) load: $(cat /proc/loadavg)" > ${BASE}/bench-out/meta.txt
declare -A N=([keygen]=3000 [sign]=1500 [verify]=6000)
for r in $(seq 1 $ROUNDS); do
  for pair in $(for i in aws118 aws118noavx2 aws116 nx na nc; do for o in keygen sign verify; do echo "$i:$o"; done; done | shuf); do
    i=${pair%%:*}; o=${pair##*:}
    case $i in
      aws116) line=$(taskset -c $CORE $B116 aws116 $o ${N[$o]}) ;;
      aws118noavx2) line=$(OPENSSL_ia32cap='~0:~0x20' taskset -c $CORE $B $i $o ${N[$o]}) ;;
      *) line=$(taskset -c $CORE $B $i $o ${N[$o]}) ;;
    esac
    echo "$r $line $(cut -d' ' -f1 /proc/loadavg)" >> $OUT
  done
done
echo "end $(date -Is) load: $(cat /proc/loadavg)" >> ${BASE}/bench-out/meta.txt
echo BENCHDONE >> ${BASE}/bench-out/meta.txt
