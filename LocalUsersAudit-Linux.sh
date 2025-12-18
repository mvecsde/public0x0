#!/usr/bin/env bash
set -u -o pipefail
umask 077

# --- Must be run as root / privileged ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: This script must be run as root (or root-equivalent). Exiting."
  exit 1
fi

OUT_DIR="/var/tmp/localuser_audit"

host_fqdn="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown")"
host_short="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo "unknown")"
safe_host="$(echo "$host_short" | sed 's/[^A-Za-z0-9_.-]/_/g')"

report_date="$(date -u +%F)"   # yyyy-mm-dd (UTC)
OUT_FILE="${OUT_DIR}/Linux_LocalUsers_${safe_host}-${report_date}.csv"

mkdir -p "$OUT_DIR" 2>/dev/null || true
chmod 700 "$OUT_DIR" 2>/dev/null || true

uid_min="$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
uid_min="${uid_min:-1000}"

csv_escape() { local s="${1:-}"; s="${s//\"/\"\"}"; printf "\"%s\"" "$s"; }

# ----- PermitRootLogin (best effort) -----
permit_root_login="Unknown"
if command -v sshd >/dev/null 2>&1; then
  permit_root_login="$(
    sshd -T -C "user=root,host=localhost,addr=127.0.0.1" 2>/dev/null |
      awk '$1=="permitrootlogin"{print $2; exit}' || true
  )"
  [[ -z "${permit_root_login:-}" ]] && permit_root_login="$(
    sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}' || true
  )"
fi
[[ -z "${permit_root_login:-}" ]] && permit_root_login="Unknown"

root_ssh_login_allowed="Unknown"
case "$permit_root_login" in
  no) root_ssh_login_allowed="No" ;;
  yes|prohibit-password|without-password|forced-commands-only) root_ssh_login_allowed="Yes" ;;
  Unknown) root_ssh_login_allowed="Unknown" ;;
  *) root_ssh_login_allowed="Yes" ;;
esac

# ----- Build sudoer user/group lists (handles #include/#includedir properly) -----
declare -A seen_sudo_files=()
sudo_groups=()
sudo_users=()

queue=()
[[ -r /etc/sudoers ]] && queue+=("/etc/sudoers")
if [[ -d /etc/sudoers.d ]]; then
  while IFS= read -r -d '' f; do queue+=("$f"); done < <(find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null || true)
fi

while ((${#queue[@]})); do
  f="${queue[0]}"
  queue=("${queue[@]:1}")

  [[ -r "$f" ]] || continue
  [[ -n "${seen_sudo_files["$f"]+x}" ]] && continue
  seen_sudo_files["$f"]=1

  while IFS= read -r raw; do
    # left-trim
    line="${raw#"${raw%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue

    # Handle sudoers include directives BEFORE comment stripping
    if [[ "$line" =~ ^#includedir[[:space:]]+(.+) ]]; then
      incdir="${BASH_REMATCH[1]}"
      incdir="${incdir%/}"
      if [[ -d "$incdir" ]]; then
        while IFS= read -r -d '' ff; do queue+=("$ff"); done < <(find "$incdir" -maxdepth 1 -type f -print0 2>/dev/null || true)
      fi
      continue
    fi
    if [[ "$line" =~ ^#include[[:space:]]+(.+) ]]; then
      incfile="${BASH_REMATCH[1]}"
      [[ -r "$incfile" ]] && queue+=("$incfile")
      continue
    fi

    # Skip pure comments
    [[ "$line" =~ ^# ]] && continue

    # Strip inline comments
    line="${line%%#*}"
    # normalize spaces
    line="$(echo "$line" | sed 's/[[:space:]]\+/ /g;s/^ //;s/ $//')"
    [[ -z "$line" ]] && continue

    first="$(awk '{print $1}' <<<"$line" 2>/dev/null || true)"
    [[ -z "$first" ]] && continue

    # Ignore non-rule lines
    case "$first" in
      Defaults|User_Alias|Host_Alias|Cmnd_Alias|Runas_Alias|Include|includedir) continue ;;
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

dedup() { awk 'NF && !seen[$0]++' 2>/dev/null || true; }
mapfile -t sudo_groups < <(printf "%s\n" "${sudo_groups[@]}" | dedup | sort 2>/dev/null || true)
mapfile -t sudo_users  < <(printf "%s\n" "${sudo_users[@]}"  | dedup | sort 2>/dev/null || true)

# ----- su restriction (pam_wheel) -----
su_restricted="No"
su_group=""
if [[ -r /etc/pam.d/su ]]; then
  wheel_line="$(awk '$0 !~ /^[[:space:]]*#/ && $0 ~ /pam_wheel\.so/ {print; exit}' /etc/pam.d/su 2>/dev/null || true)"
  if [[ -n "${wheel_line:-}" ]]; then
    su_restricted="Yes"
    if grep -qE 'group=' <<<"$wheel_line" 2>/dev/null; then
      su_group="$(sed -nE 's/.*group=([A-Za-z0-9_.-]+).*/\1/p' <<<"$wheel_line" | head -n1)"
    else
      su_group="wheel"
    fi
  fi
fi

# ----- Create CSV immediately (so it always exists) -----
{
  echo "Server,Hostname,PermitRootLogin,RootSSHLoginAllowed,Username,UID,UID0,SystemAccount,Shell,InteractiveByShell,Locked,Groups,SudoersEffective,SudoReason,SuRestricted,SuGroup,SuEligible,Privileged,PrivReason,LastLogin"
} > "$OUT_FILE" 2>/dev/null || { echo "ERROR: Could not write $OUT_FILE"; exit 2; }

while IFS=: read -r user _ uid _ _ _ shell; do
  [[ -z "$user" ]] && continue
  [[ -z "${uid:-}" ]] && continue

  uid0=$([[ "$uid" -eq 0 ]] && echo "Yes" || echo "No")
  system=$([[ "$uid" -lt "$uid_min" ]] && echo "Yes" || echo "No")
  case "$shell" in */false|*/nologin) interactive="No" ;; *) interactive="Yes" ;; esac

  locked="Unknown"
  if [[ -r /etc/shadow ]]; then
    pw="$(awk -F: -v u="$user" '$1==u{print $2}' /etc/shadow 2>/dev/null || true)"
    if [[ "$pw" == "!"* || "$pw" == "*"* ]]; then locked="Yes"; else locked="No"; fi
  fi

  groups="$(id -nG "$user" 2>/dev/null | tr ' ' ';' || true)"

  sudo_effective="No"
  sudo_reason=""
  if printf "%s\n" "${sudo_users[@]}" | grep -qx "$user" 2>/dev/null; then
    sudo_effective="Yes"; sudo_reason="direct sudoers rule"
  else
    for g in "${sudo_groups[@]}"; do
      [[ -z "$g" ]] && continue
      if [[ ";$groups;" == *";$g;"* ]]; then
        sudo_effective="Yes"; sudo_reason="member of sudoers group: $g"; break
      fi
    done
  fi

  su_eligible="No"
  if [[ "$su_restricted" == "Yes" && -n "$su_group" ]]; then
    [[ ";$groups;" == *";$su_group;"* ]] && su_eligible="Yes"
  fi

  privileged="No"; reasons=()
  [[ "$uid0" == "Yes" ]] && { privileged="Yes"; reasons+=("uid0"); }
  [[ "$sudo_effective" == "Yes" ]] && { privileged="Yes"; reasons+=("sudo"); }
  [[ "$su_eligible" == "Yes" ]] && { privileged="Yes"; reasons+=("su"); }
  priv_reason=$(IFS='+'; echo "${reasons[*]:-none}")

  last_login="Unknown"
  if command -v lastlog >/dev/null 2>&1; then
    last_login="$(lastlog -u "$user" 2>/dev/null | awk 'NR==2{ $1=""; sub(/^ +/,""); print }' || true)"
    [[ -z "${last_login:-}" ]] && last_login="Unknown"
  fi

  # Show PermitRootLogin / RootSSHLoginAllowed ONLY on the root row
  prl_out=""
  rsla_out=""
  if [[ "$user" == "root" ]]; then
    prl_out="$permit_root_login"
    rsla_out="$root_ssh_login_allowed"
  fi

  printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$(csv_escape "$host_fqdn")" \
    "$(csv_escape "$host_short")" \
    "$(csv_escape "$prl_out")" \
    "$(csv_escape "$rsla_out")" \
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
    >> "$OUT_FILE" 2>/dev/null || true
done < /etc/passwd

echo "OK: Wrote $OUT_FILE"
ls -l "$OUT_FILE" 2>/dev/null || true
