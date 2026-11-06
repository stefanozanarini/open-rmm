# open-rmm reboot module (Linux): the same reboot policy as on Windows.
# Other modules never reboot: they report that a reboot is pending, and this
# module applies the policy. When to reboot is decided by the policy rule
# window.
#
# Parameters (defaults in brackets): only_if_pending [true],
# min_pending_hours [0], notice_minutes [15], skip_if_user [false],
# min_battery_percent [30], message.
. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"
rmm_read_request

export LC_ALL=C

s() { printf '"%s"' "$(rmm_json_escape "$1")"; }

# Parameters are read without jq: the agent serializes the request itself.
param() { # name, default
  v=$(printf '%s' "$OPENRMM_REQUEST" | sed -n "s/.*\"$1\":\(true\|false\|[0-9][0-9]*\).*/\1/p")
  printf '%s' "${v:-$2}"
}
param_text() { # name
  printf '%s' "$OPENRMM_REQUEST" | sed -n "s/.*\"$1\":\"\(\([^\"\\\\]\|\\\\.\)*\)\".*/\1/p" | sed 's/\\\(.\)/\1/g'
}

# pending prints "required<TAB>since<TAB>reasons (JSON list items)".
pending() {
  for f in /run/reboot-required /var/run/reboot-required /run/reboot-needed; do
    if [ -e "$f" ]; then
      printf 'true\t%s\t"packages"\n' "$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
      return
    fi
  done
  if command -v needs-restarting >/dev/null 2>&1; then
    needs-restarting -r >/dev/null 2>&1
    [ $? -eq 1 ] && { printf 'true\t\t"packages"\n'; return; }
  elif command -v zypper >/dev/null 2>&1; then
    zypper -n -q needs-rebooting >/dev/null 2>&1
    [ $? -eq 102 ] && { printf 'true\t\t"packages"\n'; return; }
  fi
  if command -v rpm >/dev/null 2>&1; then
    newest=$(rpm -q --last kernel kernel-core kernel-default 2>/dev/null | awk '/^kernel/ { print $1; exit }' | sed 's/^kernel\(-core\|-default\)\{0,1\}-//')
    case "$(uname -r)" in
    "$newest"*) ;;
    *) [ -n "$newest" ] && { printf 'true\t\t"kernel"\n'; return; } ;;
    esac
  fi
  printf 'false\t\t\n'
}

skip() { # reason
  rmm_result "{\"action\":\"skipped\",\"reason\":$(s "$1"),\"pending\":$required,\"reasons\":[$reasons]}"
  exit 0
}

case "$(rmm_action)" in
reboot)
  p=$(pending)
  required=$(printf '%s' "$p" | cut -f1)
  since=$(printf '%s' "$p" | cut -f2)
  reasons=$(printf '%s' "$p" | cut -f3)
  if [ "$(param only_if_pending true)" = true ] && [ "$required" != true ]; then
    skip "nessun riavvio in sospeso"
  fi
  min_hours=$(param min_pending_hours 0)
  if [ "$required" = true ] && [ "$min_hours" -gt 0 ] && [ -n "$since" ]; then
    age=$(( ($(date +%s) - $(date -d "$since" +%s)) / 3600 ))
    [ "$age" -lt "$min_hours" ] && skip "riavvio in sospeso da meno di $min_hours ore"
  fi
  min_battery=$(param min_battery_percent 30)
  for b in /sys/class/power_supply/BAT*; do
    [ -r "$b/capacity" ] || continue
    if [ "$(cat "$b/status" 2>/dev/null)" = Discharging ] && [ "$(cat "$b/capacity")" -lt "$min_battery" ]; then
      skip "a batteria con carica $(cat "$b/capacity")%"
    fi
  done
  users=$(who 2>/dev/null | awk '{ print $1 }' | sort -u | grep -c . || true)
  [ "$users" -gt 0 ] && [ "$(param skip_if_user false)" = true ] && skip "utente collegato"
  if [ -e /run/systemd/shutdown/scheduled ]; then
    rmm_result "{\"action\":\"already_scheduled\",\"pending\":$required,\"reasons\":[$reasons]}"
    exit 0
  fi
  minutes=1
  [ "$users" -gt 0 ] && minutes=$(param notice_minutes 15)
  [ "$minutes" -lt 1 ] && minutes=1
  [ "$minutes" -gt 1440 ] && minutes=1440
  message=$(param_text message)
  [ -n "$message" ] || message="Il computer verrà riavviato tra $minutes minuti per completare gli aggiornamenti. Salva il lavoro."
  message=$(printf '%s' "$message" | cut -c1-500)
  if ! out=$(shutdown -r "+$minutes" "$message" 2>&1); then
    rmm_error "shutdown failed: $out"
    exit 1
  fi
  rmm_log "reboot scheduled in $minutes minutes"
  rmm_result "{\"action\":\"scheduled\",\"delay_seconds\":$((minutes * 60)),\"users_logged_on\":$users,\"pending\":$required,\"reasons\":[$reasons]}"
  ;;
*)
  rmm_error "unknown action"
  exit 1
  ;;
esac
