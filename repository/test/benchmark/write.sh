#!/usr/bin/env bash

# Configuration
OYDID_CMD="${OYDID_CMD:-oydid}"
MEASUREMENTS=20
DIDS_FILE="oydid_dids_for_read.txt"
MAX_UPDATES_PER_DID=4
MIN_CREATES=4
MAX_CREATES=6

# Optional: different payload sizes (bytes) for random JSON bodies
PAYLOAD_SIZES=(128 512 2048)

# Reset DID list
: > "$DIDS_FILE"

now_ms() {
  # current time in milliseconds
  echo $(( $(date +%s%N) / 1000000 ))
}

min_ms=""
max_ms=""
sum_ms=0

echo "OYDID Write Benchmark"
echo "Measurements   : $MEASUREMENTS"
echo "DIDs list file : $DIDS_FILE"
echo "----------------------------------------"

for m in $(seq 1 "$MEASUREMENTS"); do
  start_ms=$(now_ms)
  num_creates=$(( RANDOM % (MAX_CREATES - MIN_CREATES + 1) + MIN_CREATES ))
  total_ops=0
  for _ in $(seq 1 "$num_creates"); do
    size_idx=$(( RANDOM % ${#PAYLOAD_SIZES[@]} ))
    payload_size=${PAYLOAD_SIZES[$size_idx]}
    random_data=$(head -c "$payload_size" /dev/urandom | base64 | tr -d '\n' | cut -c1-"$payload_size")
    doc="{\"data\":\"$random_data\"}"
    did=$(echo "$doc" | oydid create -l http://localhost:3300 --json-output | jq -r .did)

    echo "$did" >> "$DIDS_FILE"
    total_ops=$((total_ops + 1))
    num_updates=$(( RANDOM % (MAX_UPDATES_PER_DID + 1) ))
    for _ in $(seq 1 "$num_updates"); do
      size_idx=$(( RANDOM % ${#PAYLOAD_SIZES[@]} ))
      payload_size=${PAYLOAD_SIZES[$size_idx]}
      random_data=$(head -c "$payload_size" /dev/urandom | base64 | tr -d '\n' | cut -c1-"$payload_size")
      update_doc="{\"data\":\"$random_data\"}"
      did=$(echo "$update_doc" | oydid update $did -l http://localhost:3300 --json-output | jq -r .did)
      echo "$did" >> "$DIDS_FILE"
      total_ops=$((total_ops + 1))
    done
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
  echo "Measurement $m: ${duration} ms (${total_ops} operations)"
done

avg_ms=$((sum_ms / MEASUREMENTS))
echo "----------------------------------------"
echo "Number of measurements : $MEASUREMENTS"
echo "Min duration           : ${min_ms} ms"
echo "Max duration           : ${max_ms} ms"
echo "Average duration       : ${avg_ms} ms"
echo "DIDs stored in         : $DIDS_FILE"