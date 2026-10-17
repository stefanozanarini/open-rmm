. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"
rmm_read_request

case "$(rmm_action)" in
info)
  os=""
  if [ -r /etc/os-release ]; then
    os=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")
  fi
  uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
  rmm_progress 50 "operating system read"
  rmm_result "{\"hostname\":\"$(rmm_json_escape "$(uname -n)")\",\"os\":\"$(rmm_json_escape "$os")\",\"kernel\":\"$(rmm_json_escape "$(uname -r)")\",\"uptime_seconds\":${uptime:-0}}"
  ;;
*)
  rmm_error "unknown action"
  exit 1
  ;;
esac
