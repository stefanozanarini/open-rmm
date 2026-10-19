# open-rmm inventory module (Linux). Read-only. Collects a subset of the
# Windows inventory: system, OS, CPU, memory, disks and packages.
. "$OPENRMM_MODULE_DIR/_sdk/openrmm.sh"
rmm_read_request

s() { printf '"%s"' "$(rmm_json_escape "$1")"; }
dmi() { cat "/sys/class/dmi/id/$1" 2>/dev/null | head -n 1; }

collect() {
  rmm_progress 10 "system" >&3
  name="" version=""
  if [ -r /etc/os-release ]; then
    name=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")
    version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
  fi
  boot=""
  if up=$(cut -d. -f1 /proc/uptime 2>/dev/null); then
    boot=$(date -u -d "@$(( $(date +%s) - up ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
  fi
  virt=false
  case "$(dmi sys_vendor) $(dmi product_name)" in
    *VMware*|*VirtualBox*|*QEMU*|*KVM*|*Xen*|*"Virtual Machine"*|*Parallels*) virt=true ;;
  esac
  uefi=false
  [ -d /sys/firmware/efi ] && uefi=true

  cpus=$(awk -F': ' '/^model name/ { if (!seen[$2]++) { n++; name[n]=$2 } } END {
    for (i = 1; i <= n; i++) { gsub(/\\/, "\\\\", name[i]); gsub(/"/, "\\\"", name[i]); printf "%s{\"name\":\"%s\"}", (i>1?",":""), name[i] } }' /proc/cpuinfo 2>/dev/null)
  mem=$(awk '/^MemTotal:/ { printf "%d", $2 * 1024 }' /proc/meminfo 2>/dev/null)

  rmm_progress 40 "disks" >&3
  disks=""
  if command -v lsblk >/dev/null 2>&1; then
    disks=$(lsblk -dbnr -o NAME,SIZE,ROTA,TYPE 2>/dev/null | awk '$4 == "disk" {
      printf "%s{\"model\":\"%s\",\"size_bytes\":%s,\"media_type\":\"%s\"}", (n++?",":""), $1, $2, ($3 == "1" ? "HDD" : "SSD") }')
  fi

  rmm_progress 60 "software" >&3
  sw=""
  if command -v dpkg-query >/dev/null 2>&1; then
    sw=$(dpkg-query -W -f '${Package}\t${Version}\t${Maintainer}\n' 2>/dev/null)
  elif command -v rpm >/dev/null 2>&1; then
    sw=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n' 2>/dev/null)
  fi
  software=$(printf '%s\n' "$sw" | awk -F'\t' 'NF >= 1 && $1 != "" {
    for (i = 1; i <= 3; i++) { gsub(/\\/, "\\\\", $i); gsub(/"/, "\\\"", $i); gsub(/[\001-\037]/, "", $i) }
    printf "%s{\"name\":\"%s\",\"version\":\"%s\",\"publisher\":\"%s\",\"scope\":\"machine\"}", (n++?",":""), $1, $2, $3 }')

  printf '{"schema":1,"collected_at":"%s",' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '"system":{"manufacturer":%s,"model":%s,"serial":%s,"virtual":%s},' \
    "$(s "$(dmi sys_vendor)")" "$(s "$(dmi product_name)")" "$(s "$(dmi product_serial)")" "$virt"
  printf '"os":{"name":%s,"version":%s,"build":%s,"architecture":%s' \
    "$(s "$name")" "$(s "$version")" "$(s "$(uname -r)")" "$(s "$(uname -m)")"
  [ -n "$boot" ] && printf ',"last_boot":"%s"' "$boot"
  printf '},"firmware":{"vendor":%s,"version":%s,"date":%s,"uefi":%s},' \
    "$(s "$(dmi bios_vendor)")" "$(s "$(dmi bios_version)")" "$(s "$(dmi bios_date)")" "$uefi"
  printf '"cpus":[%s],"memory":{"total_bytes":%s},"disks":[%s],"software":[%s],"remote_access":{}}' \
    "$cpus" "${mem:-0}" "$disks" "$software"
}

case "$(rmm_action)" in
collect)
  # Progress events go to fd 3 (the real stdout) while the JSON is captured.
  exec 3>&1
  data=$(collect)
  rmm_result "$data"
  ;;
*)
  rmm_error "unknown action"
  exit 1
  ;;
esac
