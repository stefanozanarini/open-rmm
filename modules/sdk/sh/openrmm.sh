# open-rmm module SDK for POSIX shell (protocol version 1).
#
#   . "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"
#   rmm_read_request
#   case "$(rmm_action)" in
#     info) rmm_result "{\"kernel\":\"$(rmm_json_escape "$(uname -r)")\"}" ;;
#     *)    rmm_error "unknown action" ;;
#   esac
#
# The raw request JSON is in $OPENRMM_REQUEST; parameters are best read with
# jq when available (rmm_params prints the params object).

rmm_read_request() {
  IFS= read -r OPENRMM_REQUEST || true
  if [ -z "$OPENRMM_REQUEST" ]; then
    rmm_error "no request received from the agent"
    exit 1
  fi
}

# rmm_action prints the requested action. The agent serializes the request
# itself, and action names are restricted to [a-z0-9_-].
rmm_action() {
  printf '%s' "$OPENRMM_REQUEST" | sed -n 's/.*"action":"\([a-z0-9_-]*\)".*/\1/p'
}

rmm_params() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$OPENRMM_REQUEST" | jq -c '.params'
  else
    return 1
  fi
}

# rmm_json_escape prints $1 as the inside of a JSON string.
rmm_json_escape() {
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g' -e 's/\r/\\r/g' \
    | awk 'NR > 1 { printf "\\n" } { printf "%s", $0 }'
}

rmm_progress() { printf '{"type":"progress","percent":%d,"message":"%s"}\n' "$1" "$(rmm_json_escape "${2:-}")"; }
rmm_log()      { printf '{"type":"log","level":"%s","message":"%s"}\n' "${2:-info}" "$(rmm_json_escape "$1")"; }
# rmm_result takes an already serialized JSON value.
rmm_result()   { printf '{"type":"result","data":%s}\n' "$1"; }
rmm_error()    { printf '{"type":"error","message":"%s"}\n' "$(rmm_json_escape "$1")"; }
