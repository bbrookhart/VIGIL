#!/usr/bin/env bash
# Run a curl-compatible command. Only an explicit timeout with HTTP 000 represents
# the expected network-policy drop; command, DNS and connection errors stay distinct.
probe_http() {
  local code status=0
  code="$("$@")" || status=$?
  if [[ "$status" == "0" ]]; then
    printf '%s' "$code"
  elif [[ "$status" == "28" && "$code" == "000" ]]; then
    printf '000'
  else
    printf 'transport-error-%s' "$status"
  fi
}
