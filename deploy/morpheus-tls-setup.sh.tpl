#!/bin/bash
# morpheus-tls-setup - one-time root-side setup for the Morpheus "TLS Appliance Certificate" plugin.
#
# Run as root on the appliance (the plugin's admin page shows a ready-to-paste command):
#   morpheus-tls-setup.sh [install|status|uninstall] [--dry-run] [--app-user NAME]
#
#   install     (default) installs the privileged helper and the sudoers rule, and - only if nginx is not already
#               using /etc/morpheus/ssl/cert.pem + key.pem - points nginx at those files (backs up /etc/morpheus,
#               seeds cert.pem/key.pem from the certificate nginx serves now, edits morpheus.rb, runs reconfigure).
#   status      read-only: prints what is in place and what is missing.
#   uninstall   removes the sudoers rule and the helper. Does not touch morpheus.rb or any certificate.
#   --dry-run   print what would be done, change nothing.
#
# Safe to run again: every step checks first and skips what is already right.
set -euo pipefail

HELPER_DST=/usr/local/sbin/morpheus-tls-helper
SUDOERS_DST=/etc/sudoers.d/morpheus-tls
SSL_DIR=/etc/morpheus/ssl
CERT="$SSL_DIR/cert.pem"
KEY="$SSL_DIR/key.pem"
RB=/etc/morpheus/morpheus.rb
CONF=/opt/morpheus/embedded/nginx/conf/sites-available/morpheus-ssl.conf
CTL=/opt/morpheus/bin/morpheus-ctl
STAMP="$(date +%Y%m%d%H%M%S)"

MODE=install; DRY=0; APP_USER=""
while [ $# -gt 0 ]; do
  case "$1" in
    install|status|uninstall) MODE="$1" ;;
    --dry-run) DRY=1 ;;
    --app-user) shift; APP_USER="${1:-}" ;;
    -h|--help) sed -n '2,15p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ok]      %s\n' "$*"; }
todo() { printf '  [missing] %s\n' "$*"; }
act()  { printf '  [do]      %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (put sudo in front of bash)"
[ -x "$CTL" ] || die "$CTL not found - is this a Morpheus appliance?"
[ -f "$RB" ] || die "$RB not found"

# ---- embedded files (single source of truth: deploy/ in the plugin repository) -----------------------------------
emit_helper() {
cat <<'LE_EMBEDDED_HELPER_EOF'
#@@HELPER@@
LE_EMBEDDED_HELPER_EOF
}
emit_sudoers() {
cat <<'LE_EMBEDDED_SUDOERS_EOF'
#@@SUDOERS@@
LE_EMBEDDED_SUDOERS_EOF
}

# ---- helpers ---------------------------------------------------------------------------------------------------
detect_app_user() {
  [ -n "$APP_USER" ] && return 0
  local users
  users="$(ps -o user:32= -C java 2>/dev/null | sort -u | grep -v '^root$' || true)"
  if [ "$(printf '%s\n' "$users" | grep -c .)" -eq 1 ]; then APP_USER="$users"; return 0; fi
  if id morpheus-app >/dev/null 2>&1; then APP_USER=morpheus-app; return 0; fi
  die "cannot tell which OS user runs Morpheus (found: ${users:-none}). Re-run with --app-user NAME"
}
conf_directive() { [ -r "$CONF" ] && sed -n -E "s/^[[:space:]]*$1[[:space:]]+([^;[:space:]]+)[[:space:]]*;.*/\1/p" "$CONF" | head -n1 || true; }
nginx_cert() { conf_directive ssl_certificate; }
nginx_key()  { conf_directive ssl_certificate_key; }
nginx_ok()   { [ "$(nginx_cert)" = "$CERT" ] && [ "$(nginx_key)" = "$KEY" ]; }
same_file()  { [ -f "$2" ] && cmp -s "$1" "$2"; }
tmp() { mktemp "${TMPDIR:-/tmp}/tls-setup.XXXXXX"; }

# ---- status ----------------------------------------------------------------------------------------------------
do_status() {
  local rc=0
  say "Setup status:"
  if [ -x "$HELPER_DST" ]; then
    local t; t="$(tmp)"; emit_helper > "$t"
    if same_file "$t" "$HELPER_DST"; then ok "helper $HELPER_DST is installed and current"
    else todo "helper $HELPER_DST differs from this version (install will update it)"; rc=1; fi
    rm -f "$t"
  else todo "helper $HELPER_DST not installed"; rc=1; fi
  if [ -f "$SUDOERS_DST" ]; then ok "sudoers rule $SUDOERS_DST present"; else todo "sudoers rule $SUDOERS_DST not installed"; rc=1; fi
  if nginx_ok; then ok "nginx uses $CERT and $KEY"
  else todo "nginx uses '$(nginx_cert)' / '$(nginx_key)', not $CERT / $KEY"; rc=1; fi
  if [ -f "$CERT" ] && [ -f "$KEY" ]; then ok "$CERT and $KEY exist"; else todo "$CERT / $KEY missing"; rc=1; fi
  return $rc
}

# ---- steps -----------------------------------------------------------------------------------------------------
step_helper() {
  local t; t="$(tmp)"; emit_helper > "$t"
  if same_file "$t" "$HELPER_DST"; then ok "helper already current"; rm -f "$t"; return; fi
  act "install helper -> $HELPER_DST"
  [ "$DRY" -eq 1 ] || install -o root -g root -m 0755 "$t" "$HELPER_DST"
  rm -f "$t"
}

step_sudoers() {
  detect_app_user
  id "$APP_USER" >/dev/null 2>&1 || die "OS user '$APP_USER' does not exist"
  local t; t="$(tmp)"
  emit_sudoers | sed -E "s/^morpheus-app[[:space:]]/$APP_USER /" > "$t"
  if same_file "$t" "$SUDOERS_DST"; then ok "sudoers rule already current (user $APP_USER)"; rm -f "$t"; return; fi
  if command -v visudo >/dev/null 2>&1; then
    visudo -cf "$t" >/dev/null || { rm -f "$t"; die "generated sudoers file did not validate - nothing was installed"; }
  fi
  act "install sudoers rule for user $APP_USER -> $SUDOERS_DST (helper + 'morpheus-ctl restart nginx' only)"
  [ "$DRY" -eq 1 ] || install -o root -g root -m 0440 "$t" "$SUDOERS_DST"
  rm -f "$t"
}

step_nginx() {
  if nginx_ok && [ -f "$CERT" ] && [ -f "$KEY" ]; then ok "nginx already uses $CERT / $KEY"; return; fi
  local cur_cert cur_key
  cur_cert="$(nginx_cert)"; cur_key="$(nginx_key)"
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    [ -n "$cur_cert" ] && [ -f "$cur_cert" ] && [ -n "$cur_key" ] && [ -f "$cur_key" ] ||
      die "cannot find the certificate nginx serves now (from $CONF) to copy it to $CERT; create $CERT and $KEY yourself and re-run"
  fi
  act "back up /etc/morpheus -> /root/etc-morpheus-backup-$STAMP.tgz (contains keys, mode 0600)"
  if [ "$DRY" -eq 0 ]; then
    ( umask 077; tar czf "/root/etc-morpheus-backup-$STAMP.tgz" /etc/morpheus 2>/dev/null )
  fi
  if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    act "copy the current certificate and key ($cur_cert, $cur_key) to $CERT and $KEY"
    if [ "$DRY" -eq 0 ]; then
      install -d -o root -g root -m 0750 "$SSL_DIR"
      install -o root -g root -m 0644 "$cur_cert" "$CERT"
      install -o root -g root -m 0600 "$cur_key" "$KEY"
    fi
  else
    ok "$CERT and $KEY already exist (kept as they are)"
  fi
  act "set nginx['ssl_certificate'] and nginx['ssl_server_key'] in $RB (backup: $RB.bak-$STAMP)"
  if [ "$DRY" -eq 0 ]; then
    cp -p "$RB" "$RB.bak-$STAMP"
    sed -i -E "/^[[:space:]]*nginx\['(ssl_certificate|ssl_server_key|ssl_certificate_key)'\][[:space:]]*=/d" "$RB"
    [ -z "$(tail -c1 "$RB")" ] || printf '\n' >> "$RB"
    {
      printf "# added by morpheus-tls-setup (TLS Appliance Certificate plugin) %s\n" "$STAMP"
      printf "nginx['ssl_certificate'] = '%s'\n" "$CERT"
      printf "nginx['ssl_server_key'] = '%s'\n" "$KEY"
    } >> "$RB"
  fi
  act "run 'morpheus-ctl reconfigure' (takes a minute or two; the web UI may blink)"
  if [ "$DRY" -eq 0 ]; then
    RLOG="/root/tls-setup-reconfigure-$STAMP.log"
    if ! "$CTL" reconfigure > "$RLOG" 2>&1; then
      tail -n 25 "$RLOG" >&2
      cp -p "$RB.bak-$STAMP" "$RB"
      die "reconfigure failed (full log: $RLOG) - $RB was restored from $RB.bak-$STAMP; full backup: /root/etc-morpheus-backup-$STAMP.tgz"
    fi
    ok "reconfigure finished (log: $RLOG)"
    if ! nginx_ok; then
      cp -p "$RB.bak-$STAMP" "$RB"
      die "nginx still does not use $CERT / $KEY after reconfigure (this Morpheus version may use another setting name). $RB was restored from $RB.bak-$STAMP; run reconfigure again to undo the change"
    fi
    ok "nginx now uses $CERT and $KEY"
  fi
}

step_verify() {
  [ "$DRY" -eq 1 ] && return 0
  say "Checking as the Morpheus app user ($APP_USER):"
  if sudo -u "$APP_USER" -- sudo -n "$HELPER_DST" version >/dev/null 2>&1; then ok "helper callable via sudo"
  else todo "helper NOT callable via sudo as $APP_USER"; return 1; fi
  if sudo -u "$APP_USER" -- sudo -n -l "$CTL" restart nginx >/dev/null 2>&1; then ok "'morpheus-ctl restart nginx' allowed"
  else todo "'morpheus-ctl restart nginx' NOT allowed for $APP_USER"; return 1; fi
}

case "$MODE" in
  status)
    do_status || { say; say "Run '... install' to fix what is missing."; exit 1; }
    ;;
  uninstall)
    say "Uninstalling (sudoers rule and helper only; morpheus.rb and certificates are left alone)"
    for f in "$SUDOERS_DST" "$HELPER_DST"; do
      if [ -e "$f" ]; then act "remove $f"; [ "$DRY" -eq 1 ] || rm -f "$f"; else ok "$f already absent"; fi
    done
    say "Note: nginx still points at $CERT / $KEY. To go back, remove the two lines marked 'morpheus-tls-setup' from $RB and reconfigure."
    ;;
  install)
    [ "$DRY" -eq 0 ] || say "DRY RUN - nothing will be changed"
    say "1/3 privileged helper";   step_helper
    say "2/3 sudoers rule";        step_sudoers
    say "3/3 nginx certificate paths"; step_nginx
    step_verify
    say
    [ "$DRY" -eq 1 ] && say "Dry run finished." || say "Setup finished. Reload the plugin's admin page - the checklist should be green."
    ;;
esac
