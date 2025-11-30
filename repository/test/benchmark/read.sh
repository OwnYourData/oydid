#!/usr/bin/env bash

# Configuration
OYDID_CMD="${OYDID_CMD:-oydid}"
DIDS_FILE="oydid_dids_for_read.txt"
MEASUREMENTS=20
READS_PER_MEASUREMENT=10

now_ms() {
  echo $(( $(date +%s%N) / 1000000 ))
}

if [ ! -f "$DIDS_FILE" ]; then
  echo "DIDs file '$DIDS_FILE' not found. Run the write benchmark first."
  exit 1
fi
ALL_DIDS=()
while IFS= read -r line; do
  [ -n "$line" ] && ALL_DIDS+=("$line")
done < "$DIDS_FILE"
if [ "${#ALL_DIDS[@]}" -eq 0 ]; then
  echo "No DIDs found in '$DIDS_FILE'."
  exit 1
fi

echo "OYDID Read Benchmark"
echo "Measurements          : $MEASUREMENTS"
echo "Reads per measurement : $READS_PER_MEASUREMENT"
echo "Total DIDs available  : ${#ALL_DIDS[@]}"
echo "----------------------------------------"

min_ms=""
max_ms=""
sum_ms=0

for m in $(seq 1 "$MEASUREMENTS"); do
  start_ms=$(now_ms)
  for _ in $(seq 1 "$READS_PER_MEASUREMENT"); do
    idx=$(( RANDOM % ${#ALL_DIDS[@]} ))
    did="${ALL_DIDS[$idx]}"
    $OYDID_CMD read "$did" >/dev/null 2>&1
  done
  end_ms=$(now_ms)
  duration=$((end_ms - start_ms))

  if [ -z "$min_ms" ] || [ "$duration" -lt "$min_ms" ]; then
    min_ms=$duration
  fi
  if [ -z "$max_ms" ] || [ "$duration" -gt "$max_ms" ]; then
    max_ms=$duration
  fi
  sum_ms=$((sum_ms + duration))
  echo "Measurement $m: ${duration} ms (${READS_PER_MEASUREMENT} resolves)"
done

avg_ms=$((sum_ms / MEASUREMENTS))
echo "----------------------------------------"
echo "Number of measurements : $MEASUREMENTS"
echo "Total reads performed  : $((MEASUREMENTS * READS_PER_MEASUREMENT))"
echo "Min duration           : ${min_ms} ms"
echo "Max duration           : ${max_ms} ms"
echo "Average duration       : ${avg_ms} ms"