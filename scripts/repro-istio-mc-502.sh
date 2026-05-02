#!/usr/bin/env bash
# Reproduces an Istio multicluster 502 when HAProxy fans out to multiple
# backends and rapid back-to-back requests cause the wrong workload identity
# to be presented on the second request.
#
# Symptom: curl http://sonarr.home.arpa then immediately
#          curl http://jellyfin.home.arpa returns 502 on the second hop.
#
# Usage:  ./scripts/repro-istio-mc-502.sh [iterations] [delay_ms] [mode]
#   iterations: number of round-trips (default 50)
#   delay_ms:   sleep between the two curls in ms (default 0 = back-to-back)
#   mode:       split  - two separate curl processes (fresh TCP each)
#               shared - one curl process hits both hosts (TCP reused to HAProxy)
#               (default: split)

set -u

ITERATIONS="${1:-50}"
DELAY_MS="${2:-0}"
MODE="${3:-split}"

HOSTS=(
  "http://sonarr.home.arpa"
  "http://jellyfin.home.arpa"
)

CURL_OPTS=(
  --silent
  --show-error
  --location
  --max-time 5
  --output /dev/null
)

# Single-curl: one TCP/TLS session reused across both hosts (-:next swaps URL)
SHARED_FMT='%{url_effective} %{http_code}\n'
SPLIT_FMT='%{http_code}'

ok=0
bad=0
declare -A code_counts

sleep_ms() {
  local ms="$1"
  [[ "$ms" -le 0 ]] && return 0
  # portable-ish ms sleep
  local s
  s=$(awk -v m="$ms" 'BEGIN{printf "%.3f", m/1000}')
  sleep "$s"
}

printf 'Reproducer: %d iterations, %dms inter-curl delay\n' "$ITERATIONS" "$DELAY_MS"
printf '  hosts: %s  ->  %s\n\n' "${HOSTS[0]}" "${HOSTS[1]}"

run_pair() {
  if [[ "$MODE" == "shared" ]]; then
    # One curl process, two URLs → TCP keep-alive reused across hosts.
    # `--next` resets per-URL options so both requests run with --location.
    curl "${CURL_OPTS[@]}" --write-out "$SHARED_FMT" \
      "${HOSTS[0]}" \
      --next "${CURL_OPTS[@]}" --write-out "$SHARED_FMT" \
      "${HOSTS[1]}" 2>&1 || true
  else
    local c1 c2
    c1=$(curl "${CURL_OPTS[@]}" --write-out "$SPLIT_FMT" "${HOSTS[0]}" 2>/dev/null || echo "ERR")
    sleep_ms "$DELAY_MS"
    c2=$(curl "${CURL_OPTS[@]}" --write-out "$SPLIT_FMT" "${HOSTS[1]}" 2>/dev/null || echo "ERR")
    printf '%s %s\n%s %s\n' "${HOSTS[0]}" "$c1" "${HOSTS[1]}" "$c2"
  fi
}

for i in $(seq 1 "$ITERATIONS"); do
  out=$(run_pair)

  pair_bad=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    code="${line##* }"
    code_counts[$code]=$(( ${code_counts[$code]:-0} + 1 ))
    if [[ "$code" == "502" || "$code" == "503" || "$code" == "504" || "$code" == "ERR" ]]; then
      pair_bad=1
      printf '%4d  BAD  %s\n' "$i" "$line"
    fi
  done <<< "$out"

  if [[ "$pair_bad" -eq 1 ]]; then
    bad=$((bad+1))
  else
    ok=$((ok+1))
    # Print a short heartbeat every 50 iters so we know it's alive.
    if (( i % 50 == 0 )); then
      printf '%4d  ok\n' "$i"
    fi
  fi
done

echo
echo "Summary:"
printf '  iterations:        %d\n' "$ITERATIONS"
printf '  pairs without 502: %d\n' "$ok"
printf '  pairs with 502:    %d\n' "$bad"
echo "  status code counts (across both curls):"
for code in "${!code_counts[@]}"; do
  printf '    %s : %d\n' "$code" "${code_counts[$code]}"
done
