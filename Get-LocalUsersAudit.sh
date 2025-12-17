#!/usr/bin/env bash
set -euo pipefail

# RunId can be:
#  - plain: 20251217_0100
#  - JSON: {"RunId":"20251217_0100"}
# Default: UTC YYYYMMDD
arg1="${1:-}"
run_id=""

if [[ -n "$arg1" ]]; then
  if [[ "$arg1" =~ ^\{ ]]; then
    run_id="$(echo "$arg1" | sed -n 's/.*"RunId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  else
    run_id="$arg1"
  fi
fi
[[ -z "${run_id:-}" ]] && run_id="$(date -u +%Y%m%d)"

OUT_DIR="/var/tmp/localuser_audit"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

host_fqdn=$(hostname -f 2>/dev/null || hostname)
host_short=$(hostname -s 2>/dev/null || hostname)

# sanitize hostname for filename safety
safe_host="$(echo "$host_short" | sed 's/[^A-Za-z0-9_.-]/_/g')"

# File naming:
OUT_FILE_COMMON="${OUT_DIR}/${run_id}_LocalUsersData.csv"                 # same name on all hosts (batch GET-friendly)
OUT_FILE_HOST="${OUT_DIR}/${run_id}_LocalUsersData_${safe_host}.csv"     # unique per host (what you want)

uid_min=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null | tail -n1)
uid_min=${uid_min:-1000}

csv_escape() {
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf "\"%s\"" "$s"
}

# --- SSH PermitRootLogin (effective-ish) ---
permit_root_login="Unknown"
if command -v sshd >/dev/null 2>&1; then
  permit_root_login=$(
    sshd -T -C "user=root,host=localhost,addr=127.0.0.1" 2>/dev/null |
      awk '$1=="permitrootlogin"{print $2; exit}'
  )
  [[ -z "${permit_root_login:-}" ]] && permit_root_login=$(
    sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}'
  )
fi

root_ssh_login_allowed="Unknown"
case "$permit_root_login" in
  no) root_ssh_login_allowed="No" ;;
  yes|prohibit-password|without-password|forced-commands-only) root_ssh_login_allowed="Yes" ;;
  *) [[ "$permit_root_login" != "Unknown" && -n "$permit_root_login" ]] && root_ssh_login_allowed="Yes" ;;
esac

# --- sudoers parsing (best-effort groups + users) ---
sudo_files=(/etc/sudoers)
if [ -d /etc/sudoers.d ]; then
  while IFS= read -r -d '' f; do sudo_files+=("$f"); done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null)
fi

sudo_groups=()
sudo_users=()

for f in "${sudo_files[@]}"; do
  [ -r "$f" ] || continue
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    first=$(awk '{print $1}' <<<"$line")
    case "$first" in
      Defaults|User_Alias|Host_Alias|Cmnd_Alias|Runas_Alias|#include|#includedir|Include|includedir) continue ;;
    esac
    if [[ "$first" == %* ]]; then
      sudo_groups+=("${first#%}")
    elif [[ "$first" == "+"* ]]; then
      continue
    else
      sudo_users+=("$first")
    fi
  done < "$f"
done

dedup() { awk 'NF && !seen[$0]++'; }
mapfile -t sudo_groups < <(printf "%s\n" "${sudo_groups[@]}" | dedup | sort)
mapfile -t sudo_users  < <(printf "%s\n" "${sudo_users[@]}"  | dedup | sort)

# su restriction (pam_wheel)
su_restricted="No"
su_group=""
if [ -r /etc/pam.d/su ]; then
  wheel_line=$(
    awk '$0 !~ /^[[:space:]]*#/ && $0 ~ /pam_wheel\.so/ {print; exit}' /etc/pam.d/su
  )
  if [[ -n "${wheel_line:-}" ]]; then
    su_restricted="Yes"
    if grep -qE 'group=' <<<"$wheel_line"; then
      su_group=$(sed -nE 's/.*group=([A-Za-z0-9_.-]+).*/\1/p' <<<"$wheel_line" | head -n1)
    else
      su_group="wheel"
    fi
  fi
fi

# Write CSV to COMMON filename first (batch GET-friendly)
{
  echo "RunId,Server,Hostname,PermitRootLogin,RootSSHLoginAllowed,Username,UID,UID0,SystemAccount,Shell,InteractiveByShell,Locked,Groups,SudoersEffective,SudoReason,SuRestricted,SuGroup,SuEligible,Privileged,PrivReason,LastLogin"
} > "$OUT_FILE_COMMON"

while IFS=: read -r user _ uid _ _ _ shell; do
  [ -z "$user" ] && continue

  uid0=$([[ "$uid" -eq 0 ]] && echo "Yes" || echo "No")
  system=$([[ "$uid" -lt "$uid_min" ]] && echo "Yes" || echo "No")

  case "$shell" in
    */false|*/nologin) interactive="No" ;;
    *) interactive="Yes" ;;
  esac

  locked="Unknown"
  if [ -r /etc/shadow ]; then
    pw=$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow)
    if [[ "$pw" == "!"* || "$pw" == "*"* ]]; then locked="Yes"; else locked="No"; fi
  fi

  groups=$(id -nG "$user" 2>/dev/null | tr ' ' ';')

  sudo_effective="Unknown"
  sudo_reason=""
  if command -v sudo >/dev/null 2>&1 && [[ "$EUID" -eq 0 ]]; then
    out=$(sudo -l -U "$user" 2>/dev/null || true)
    if grep -qiE 'is not allowed to run sudo' <<<"$out"; then
      sudo_effective="No"
    elif grep -qiE 'may run the following commands|may run the following' <<<"$out"; then
      sudo_effective="Yes"
      sudo_reason="sudo -l -U evaluation"
    else
      sudo_effective="No"
    fi
  else
    sudo_effective="No"
    if printf "%s\n" "${sudo_users[@]}" | grep -qx "$user"; then
      sudo_effective="Yes"; sudo_reason="direct sudoers rule"
    else
      for g in "${sudo_groups[@]}"; do
        [[ -z "$g" ]] && continue
        if [[ ";$groups;" == *";$g;"* ]]; then
          sudo_effective="Yes"; sudo_reason="member of sudoers group: $g"; break
        fi
      done
    fi
  fi

  su_eligible="No"
  if [[ "$su_restricted" == "Yes" && -n "$su_group" ]]; then
    [[ ";$groups;" == *";$su_group;"* ]] && su_eligible="Yes"
  fi

  privileged="No"
  reasons=()
  [[ "$uid0" == "Yes" ]] && { privileged="Yes"; reasons+=("uid0"); }
  [[ "$sudo_effective" == "Yes" ]] && { privileged="Yes"; reasons+=("sudo"); }
  [[ "$su_eligible" == "Yes" ]] && { privileged="Yes"; reasons+=("su"); }
  priv_reason=$(IFS='+'; echo "${reasons[*]:-none}")

  last_login="Unknown"
  if command -v lastlog >/dev/null 2>&1; then
    last_login=$(lastlog -u "$user" 2>/dev/null | awk 'NR==2{ $1=""; sub(/^ +/,""); print }')
    [[ -z "${last_login:-}" ]] && last_login="Unknown"
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(csv_escape "$run_id")" \
    "$(csv_escape "$host_fqdn")" \
    "$(csv_escape "$safe_host")" \
    "$(csv_escape "$permit_root_login")" \
    "$(csv_escape "$root_ssh_login_allowed")" \
    "$(csv_escape "$user")" \
    "$(csv_escape "$uid")" \
    "$(csv_escape "$uid0")" \
    "$(csv_escape "$system")" \
    "$(csv_escape "$shell")" \
    "$(csv_escape "$interactive")" \
    "$(csv_escape "$locked")" \
    "$(csv_escape "$groups")" \
    "$(csv_escape "$sudo_effective")" \
    "$(csv_escape "$sudo_reason")" \
    "$(csv_escape "$su_restricted")" \
    "$(csv_escape "$su_group")" \
    "$(csv_escape "$su_eligible")" \
    "$(csv_escape "$privileged")" \
    "$(csv_escape "$priv_reason")" \
    "$(csv_escape "$last_login")" \
    >> "$OUT_FILE_COMMON"
done < /etc/passwd

# Copy to host-unique filename (what you want for downstream file organization)
cp -f "$OUT_FILE_COMMON" "$OUT_FILE_HOST"

echo "Wrote:"
echo "  $OUT_FILE_COMMON"
echo "  $OUT_FILE_HOST"
