# open-rmm osupdate module (Linux): operating system updates with the
# distribution's package manager.
#
#   apt     Debian, Ubuntu           security = from a *-security archive
#   dnf/yum RHEL, Rocky, Alma, CentOS security = updateinfo advisories
#   zypper  SUSE                     security = patches of category security
#
# The report has the shape of the winupdate one (updates with a
# classification, pending_reboot), so the console shows both alike.
#
# scan     refresh the package lists, report available updates and reboot
# install  { "security_only": false, "packages": ["openssl"] }  (no packages:
#          all, or all security updates); never reboots
. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"
rmm_read_request

export LC_ALL=C DEBIAN_FRONTEND=noninteractive

s() { printf '"%s"' "$(rmm_json_escape "$1")"; }

manager() {
  for m in apt-get dnf yum zypper; do
    if command -v "$m" >/dev/null 2>&1; then
      [ "$m" = apt-get ] && m=apt
      printf '%s' "$m"
      return
    fi
  done
}

# Each lister prints "name<TAB>installed<TAB>available<TAB>class<TAB>severity"
# lines, class being security or update.

list_apt() {
  apt-get -qq -o DPkg::Lock::Timeout=300 update >/dev/null 2>&1 || rmm_log "apt-get update failed: using the cached package lists" warn >&3
  apt list --upgradable 2>/dev/null | awk '
    /\[upgradable from: / {
      split($1, a, "/"); name = a[1]; origins = a[2]
      inst = $0; sub(/.*\[upgradable from: /, "", inst); sub(/\].*/, "", inst)
      class = (origins ~ /security/) ? "security" : "update"
      printf "%s\t%s\t%s\t%s\t\n", name, inst, $2, class
    }'
}

list_rpm() { # $1: dnf or yum
  tmp=$(mktemp -d)
  "$1" -q updateinfo list --security 2>/dev/null | awk '
    NF >= 3 && $2 ~ /\// {
      nvra = $3; sub(/\.[^.]+$/, "", nvra)          # arch
      n = split(nvra, p, "-"); name = p[1]
      for (i = 2; i <= n - 2; i++) name = name "-" p[i]
      sev = $2; sub(/\/.*/, "", sev)
      print name "\t" sev
    }' >"$tmp/security"
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' >"$tmp/installed" 2>/dev/null
  "$1" -q check-update 2>/dev/null >"$tmp/updates"
  awk -F'\t' '
    FILENAME ~ /security$/ { sev[$1] = $2; next }
    FILENAME ~ /installed$/ { inst[$1] = $2; next }
    /^Obsoleting/ { exit }
    {
      split($0, f, /[ \t]+/)
      if (f[3] == "" || f[1] !~ /\./) next
      name = f[1]; sub(/\.[^.]+$/, "", name)
      printf "%s\t%s\t%s\t%s\t%s\n", name, inst[name], f[2], (name in sev) ? "security" : "update", sev[name]
    }' "$tmp/security" "$tmp/installed" "$tmp/updates"
  rm -rf "$tmp"
}

# zypper tables: columns found by their header names.
zypper_table() { # $1: wanted columns, comma separated
  awk -F'|' -v want="$1" '
    function trim(x) { gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    !hdr && /\|/ { for (i = 1; i <= NF; i++) col[trim($i)] = i; hdr = 1; next }
    hdr && /\|/ {
      n = split(want, w, ","); line = ""
      for (i = 1; i <= n; i++) line = line (i > 1 ? "\t" : "") ((w[i] in col) ? trim($(col[w[i]])) : "")
      print line
    }'
}

list_zypper() {
  zypper -n -q refresh >/dev/null 2>&1 || rmm_log "zypper refresh failed: using the cached repositories" warn >&3
  zypper -n -q list-patches --category security 2>/dev/null | zypper_table "Name,Severity,Status,Summary" | awk -F'\t' '
    $3 == "needed" { printf "%s\t\t%s\tsecurity\t%s\n", $1, $4, $2 }'
  zypper -n -q list-updates 2>/dev/null | zypper_table "Name,Current Version,Available Version" | awk -F'\t' '
    $1 != "" { printf "%s\t%s\t%s\tupdate\t\n", $1, $2, $3 }'
}

# cve_map prints "package<TAB>CVE" for the pending security updates ($1:
# the lister's lines). apt has no local CVE list: the changelog of the new
# version names the CVEs it fixes (downloaded from the distribution).
cve_map() {
  case "$PM" in
  dnf | yum)
    if [ "$PM" = dnf ]; then
      dnf -q updateinfo list --security --with-cve 2>/dev/null
    else
      yum -q updateinfo list cves 2>/dev/null
    fi | awk '
      $1 ~ /^CVE-[0-9]+-[0-9]+$/ && NF >= 3 {
        nvra = $3; sub(/\.[^.]+$/, "", nvra)
        n = split(nvra, p, "-"); name = p[1]
        for (i = 2; i <= n - 2; i++) name = name "-" p[i]
        print name "\t" $1
      }' ;;
  zypper)
    zypper -n -q list-patches --cve --category security 2>/dev/null | zypper_table "No.,Patch,Status" | awk -F'\t' '
      $1 ~ /^CVE-[0-9]+-[0-9]+$/ && $3 == "needed" { print $2 "\t" $1 }' ;;
  apt)
    # Security updates grouped by source package: one changelog each.
    printf '%s\n' "$1" | awk -F'\t' '$4 == "security" { print $1 "\t" $3 }' | while IFS="$(printf '\t')" read -r pkg ver; do
      printf '%s\t%s\t%s\n' "$(dpkg-query -W -f '${source:Package}\t${source:Version}' "$pkg" 2>/dev/null)" "$pkg" "$ver"
    done | sort -t "$(printf '\t')" -k1,1 | awk -F'\t' '
      $1 != "" { pk[$1] = pk[$1] " " $3; if (!($1 in v)) { v[$1] = $2; bin[$1] = $3 "=" $4 }; if (!($1 in order)) order[$1] = ++n; }
      END { for (s in v) print order[s] "\t" s "\t" v[s] "\t" bin[s] "\t" pk[s] }' | sort -n | head -n 60 |
      while IFS="$(printf '\t')" read -r _ _ installed bin group; do
        timeout 30 apt-get -qq changelog "$bin" 2>/dev/null | awk -v stop="($installed)" '
          /^[^ \t]/ && index($0, stop) { exit }
          { while (match($0, /CVE-[0-9]+-[0-9]+/)) { print substr($0, RSTART, RLENGTH); $0 = substr($0, RSTART + RLENGTH) } }' |
          sort -u | while read -r cve; do
            for p in $group; do printf '%s\t%s\n' "$p" "$cve"; done
          done
      done ;;
  esac
}

list_updates() {
  case "$PM" in
  apt) list_apt ;;
  dnf | yum) list_rpm "$PM" ;;
  zypper) list_zypper ;;
  esac
}

# reboot prints "required<TAB>since<TAB>reason".
reboot_state() {
  for f in /run/reboot-required /var/run/reboot-required /run/reboot-needed; do
    if [ -e "$f" ]; then
      printf 'true\t%s\t%s\n' "$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" "$(head -n 3 /run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
      return
    fi
  done
  case "$PM" in
  dnf | yum)
    nr=""
    if command -v needs-restarting >/dev/null 2>&1; then
      nr=needs-restarting
    elif [ "$PM" = dnf ] && dnf needs-restarting --help >/dev/null 2>&1; then
      nr="dnf needs-restarting"
    fi
    if [ -n "$nr" ]; then
      # Exit code 1: a reboot is needed; anything else is no or unknown.
      $nr -r >/dev/null 2>&1
      [ $? -eq 1 ] && { printf 'true\t\tneeds-restarting\n'; return; }
      printf 'false\t\t\n'
      return
    fi
    newest=$(rpm -q --last kernel kernel-core 2>/dev/null | awk '/^kernel/ { print $1; exit }' | sed 's/^kernel\(-core\)\{0,1\}-//')
    if [ -n "$newest" ] && [ "$newest" != "$(uname -r)" ]; then
      printf 'true\t\tkernel %s\n' "$newest"
      return
    fi
    ;;
  zypper)
    zypper -n -q needs-rebooting >/dev/null 2>&1
    [ $? -eq 102 ] && { printf 'true\t\tzypper\n'; return; }
    ;;
  esac
  printf 'false\t\t\n'
}

report() {
  rmm_progress 10 "refreshing the package lists ($PM)" >&3
  updates=$(list_updates)
  rmm_progress 80 "reboot" >&3
  rb=$(reboot_state)
  required=$(printf '%s' "$rb" | cut -f1)
  since=$(printf '%s' "$rb" | cut -f2)
  reason=$(printf '%s' "$rb" | cut -f3)
  rmm_progress 60 "CVE" >&3
  cvefile=$(mktemp)
  # The first line keeps NR == FNR true only while reading this file.
  { printf '#\t#\n'; cve_map "$updates"; } >"$cvefile"
  items=$(printf '%s\n' "$updates" | awk -F'\t' '
    function esc(x) { gsub(/\\/, "\\\\", x); gsub(/"/, "\\\"", x); gsub(/[\001-\037]/, "", x); return x }
    NR == FNR { if ($1 == "#") next; if (!(($1, $2) in seen)) { seen[$1, $2] = 1; cves[$1] = cves[$1] (cves[$1] == "" ? "" : ",") "\"" $2 "\"" }; next }
    $1 != "" {
      title = $1 ($3 != "" ? " " $3 : "")
      printf "%s{\"id\":\"%s\",\"title\":\"%s\",\"classification\":\"%s\",\"severity\":\"%s\",\"installed\":\"%s\",\"version\":\"%s\"%s}",
        (n++ ? "," : ""), esc($1), esc(title), $4, esc(toupper(substr($5, 1, 1)) tolower(substr($5, 2))), esc($2), esc($3),
        ($1 in cves) ? ",\"cves\":[" cves[$1] "]" : ""
    }' "$cvefile" -)
  rm -f "$cvefile"
  security=$(printf '%s\n' "$updates" | awk -F'\t' '$4 == "security"' | grep -c . || true)
  total=$(printf '%s\n' "$updates" | grep -c . || true)
  other=$((total - security))
  if [ "$security" -gt 0 ]; then
    upd="{\"id\":\"updates\",\"status\":\"warning\",\"summary\":\"$security aggiornamenti di sicurezza da installare\"}"
  else
    upd="{\"id\":\"updates\",\"status\":\"ok\",\"summary\":\"Nessun aggiornamento di sicurezza mancante ($other altri disponibili)\"}"
  fi
  if [ "$required" = true ]; then
    days=0
    if [ -n "$since" ]; then
      days=$(( ($(date +%s) - $(date -d "$since" +%s 2>/dev/null || date +%s)) / 86400 ))
    fi
    status=ok
    [ "$days" -ge 3 ] && status=warning
    rbc="{\"id\":\"reboot\",\"status\":\"$status\",\"summary\":\"Riavvio in sospeso da $days giorni\"}"
    pending="{\"required\":true"
    [ -n "$since" ] && pending="$pending,\"since\":\"$since\""
    [ -n "$reason" ] && pending="$pending,\"reasons\":[$(s "$reason")]"
    pending="$pending}"
  else
    rbc='{"id":"reboot","status":"ok","summary":"Nessun riavvio in sospeso"}'
    pending='{"required":false}'
  fi
  os=""
  [ -r /etc/os-release ] && os=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")
  printf '{"managed_by":"none","manager":"%s","os":%s,"scanned_at":"%s","updates":[%s],"pending_reboot":%s,"checks":[%s,%s]' \
    "$PM" "$(s "$os")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$items" "$pending" "$upd" "$rbc"
}

# install_updates prints "exit code<TAB>last lines of output"; it uses
# $security_only and $pkgs (validated).
install_updates() {
  if [ -z "$pkgs" ] && [ "$security_only" = true ]; then
    case "$PM" in
    apt) pkgs=$(list_apt | awk -F'\t' '$4 == "security" { print $1 }')
      [ -z "$pkgs" ] && { printf '0\tno security updates\n'; return; } ;;
    esac
  fi
  log=$(mktemp)
  case "$PM" in
  apt)
    if [ -n "$pkgs" ]; then
      # shellcheck disable=SC2086
      apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --only-upgrade $pkgs >"$log" 2>&1
    else
      apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade --with-new-pkgs >"$log" 2>&1
    fi ;;
  dnf | yum)
    sec=""
    [ "$security_only" = true ] && sec=--security
    # shellcheck disable=SC2086
    "$PM" -y -q upgrade $sec $pkgs >"$log" 2>&1 ;;
  zypper)
    if [ -n "$pkgs" ]; then
      # shellcheck disable=SC2086
      zypper -n -q update $pkgs >"$log" 2>&1
    elif [ "$security_only" = true ]; then
      zypper -n -q patch --category security >"$log" 2>&1
    else
      zypper -n -q patch >"$log" 2>&1 && zypper -n -q update >>"$log" 2>&1
    fi ;;
  esac
  code=$?
  # zypper: 102/103 mean success with a reboot or a second run needed.
  [ "$PM" = zypper ] && { [ "$code" -eq 102 ] || [ "$code" -eq 103 ]; } && code=0
  printf '%s\t%s\n' "$code" "$(tail -n 8 "$log")"
  rm -f "$log"
}

PM=$(manager)
if [ -z "$PM" ]; then
  rmm_error "no supported package manager (apt, dnf, yum, zypper) on this system"
  exit 1
fi
if [ "$(id -u)" != 0 ]; then
  rmm_error "the module must run as root"
  exit 1
fi

case "$(rmm_action)" in
scan)
  # Progress events go to fd 3 (the real stdout) while the JSON is captured.
  exec 3>&1
  data=$(report)
  rmm_result "$data}"
  ;;
install)
  exec 3>&1
  security_only=false
  printf '%s' "$OPENRMM_REQUEST" | grep -q '"security_only":true' && security_only=true
  pkgs=$(printf '%s' "$OPENRMM_REQUEST" | sed -n 's/.*"packages":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | tr -d '" ')
  for p in $pkgs; do
    case "$p" in
    *[!A-Za-z0-9.+_:@-]* | -*) rmm_error "invalid package name: $p"; exit 1 ;;
    esac
  done
  rmm_progress 5 "installing ($PM)"
  out=$(install_updates)
  code=$(printf '%s\n' "$out" | head -n 1 | cut -f1)
  tail=$(printf '%s\n' "$out" | cut -f2-)
  if [ "$code" != 0 ]; then
    rmm_error "$PM exited with code $code: $tail"
    exit 1
  fi
  data=$(report)
  rmm_result "$data,\"installed\":{\"manager\":\"$PM\",\"exit_code\":$code,\"output\":$(s "$tail")}}"
  ;;
*)
  rmm_error "unknown action"
  exit 1
  ;;
esac
