#!/usr/bin/env bash
# KidGuard API – one-command deploy for a Hetzner (Ubuntu) server.
#
#   bash /opt/kidguard/backend/deploy/hetzner/deploy.sh
#
# Safe to run again at any time: it updates the code, keeps your existing .env
# (unless you choose to re-enter it), rebuilds and health-checks the API.
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ENV_FILE="$HERE/.env"
STEPS=7
step=0

bold=$'\e[1m'; green=$'\e[32m'; yellow=$'\e[33m'; red=$'\e[31m'; blue=$'\e[36m'; off=$'\e[0m'
next()  { step=$((step + 1)); printf '\n%s[%d/%d] %s%s\n' "$bold$blue" "$step" "$STEPS" "$1" "$off"; }
ok()    { printf '  %s✔%s %s\n' "$green" "$off" "$1"; }
warn()  { printf '  %s!%s %s\n' "$yellow" "$off" "$1"; }
fail()  { printf '\n%s✘ %s%s\n' "$red" "$1" "$off"; exit 1; }
trap 'fail "Stopped at step $step (line $LINENO). Copy the output above and share it."' ERR

ask() { # ask VAR "Question" "default"
  local reply; read -r -p "  $2${3:+ [$3]}: " reply; printf -v "$1" '%s' "${reply:-$3}"
}
ask_secret() { # ask_secret VAR "Question"   (input hidden)
  local reply; read -r -s -p "  $2: " reply; echo; printf -v "$1" '%s' "$reply"
}
env_get() { # tolerant of nano edits: strips CR, spaces and surrounding ' or " quotes
  { grep -E "^$1=" "$ENV_FILE" 2>/dev/null || true; } | tail -1 | cut -d= -f2- | tr -d '\r' \
    | sed -E -e 's/^[[:space:]]+//' -e 's/[[:space:]]+$//' -e "s/^'(.*)'$/\1/" -e 's/^"(.*)"$/\1/'
}
public_ip() { curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}'; }
resolve_a() { # public DNS first (what Let's Encrypt sees), then the server's resolver
  local r
  r="$(curl -fsS --max-time 6 "https://dns.google/resolve?name=$1&type=A" 2>/dev/null       | python3 -c 'import json,sys; d=json.load(sys.stdin); print(next((a["data"] for a in d.get("Answer",[]) if a.get("type")==1),""))' 2>/dev/null || true)"
  [ -n "$r" ] || r="$( { getent ahostsv4 "$1" || true; } | awk 'NR==1{print $1}')"
  printf '%s' "$r"
}
env_set() { # write KEY='value' (single quotes = literal, no $ interpolation by Docker)
  local key="$1" value="$2" tmp
  [[ "$value" == *"'"* ]] && fail "$key must not contain a single quote (')."
  tmp="$(mktemp)"
  grep -vE "^$key=" "$ENV_FILE" > "$tmp" || true
  printf "%s='%s'\n" "$key" "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"; rm -f "$tmp"
}

{ # whole script is one block: bash reads it fully before executing
[ "$(id -u)" -eq 0 ] || fail "Run as root (you are $(whoami))."
printf '%sKidGuard API deploy%s  –  repo: %s\n' "$bold" "$off" "$REPO"

# ---------------------------------------------------------------- 1. Server
next "Preparing the server (Docker, firewall, swap)"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ok "Already prepared ($(docker --version | cut -d, -f1))"
else
  warn "First run: installing Docker and hardening the server (3–5 minutes)…"
  bash "$HERE/server-setup.sh"
  ok "Server prepared"
fi

# ---------------------------------------------------------------- 2. Code
next "Updating KidGuard code from GitHub"
git config --global --add safe.directory "$REPO" >/dev/null 2>&1 || true
git -C "$REPO" pull --ff-only
ok "At commit $(git -C "$REPO" log --oneline -1)"

# ---------------------------------------------------------------- 3. Settings
next "Configuring settings (.env)"
reconfigure=y
if [ -f "$ENV_FILE" ]; then
  ask reconfigure "Settings already exist. Re-enter them? (y/N)" "n"
fi
if [[ "$reconfigure" =~ ^[Yy] ]]; then
  [ -f "$ENV_FILE" ] || cp "$HERE/.env.production.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  ip="$(public_ip)"
  echo "  Press Enter to accept the value in [brackets]. Hidden fields don't show what you type."

  ask domain "API domain (no domain? keep the free one)" "$(env_get API_DOMAIN | grep -v example.com || echo "${ip//./-}.sslip.io")"
  ask acme   "Email for the HTTPS certificate" "$(env_get ACME_EMAIL | grep -v example.com || true)"
  [ -n "$acme" ] || fail "An email is required for the HTTPS certificate."
  env_set API_DOMAIN "$domain"; env_set ACME_EMAIL "$acme"

  echo; echo "  ${bold}Database${off}: paste your Neon URL (Neon → Connect → turn OFF connection pooling)."
  ask_secret db "DATABASE_URL (Enter = keep current)"
  db="${db:-$(env_get DATABASE_URL)}"
  [[ "$db" =~ ^postgres(ql)?:// ]] || fail "DATABASE_URL must start with postgresql://"
  if [[ "$db" == *"-pooler."* ]]; then
    db="${db/-pooler./.}"; warn "Switched Neon pooled host to the direct host (needed for migrations)."
  fi
  [[ "$db" == *"sslmode="* ]] || { [[ "$db" == *"?"* ]] && db="$db&sslmode=require" || db="$db?sslmode=require"; }
  [[ "$db" == *"connection_limit="* ]] || db="$db&connection_limit=10"
  env_set DATABASE_URL "$db"

  echo; echo "  ${bold}Secrets${off}: copy them from Render → kidguard-api → Environment."
  ask_secret v "AUTH_TOKEN_SECRET from Render (keeps users logged in; Enter = generate new)"
  [ -n "$v" ] || v="$(env_get AUTH_TOKEN_SECRET | grep -v CHANGE_ME || openssl rand -hex 48)"
  [ "${#v}" -ge 32 ] || fail "AUTH_TOKEN_SECRET must be at least 32 characters."
  env_set AUTH_TOKEN_SECRET "$v"
  ask_secret v "SENDLIB_API_KEY (email OTP; Enter = keep/skip)"; [ -z "$v" ] || env_set SENDLIB_API_KEY "$v"
  ask v "SENDLIB_FROM_EMAIL" "$(env_get SENDLIB_FROM_EMAIL | grep -v your-connected || true)"; [ -z "$v" ] || env_set SENDLIB_FROM_EMAIL "$v"
  ask v "GOOGLE_CLIENT_IDS (comma separated; Enter = keep/skip)" "$(env_get GOOGLE_CLIENT_IDS)"; env_set GOOGLE_CLIENT_IDS "$v"
  ask_secret v "AI_ASSISTANT_SHARED_SECRET (same as Render; Enter = keep/skip)"; [ -z "$v" ] || env_set AI_ASSISTANT_SHARED_SECRET "$v"

  echo; echo "  ${bold}Firebase (push notifications)${off}: paste the service-account JSON, then press Enter and Ctrl+D."
  echo "  (Just press Ctrl+D to keep/skip.)"
  fb="$(cat || true)"
  if [ -n "${fb//[[:space:]]/}" ]; then
    fb="$(printf '%s' "$fb" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), separators=(",",":")))')" \
      || fail "That Firebase JSON is not valid. Paste the whole file content."
    env_set FIREBASE_SERVICE_ACCOUNT_JSON "$fb"
  fi

  # Server-only secrets that never need to match Render
  [[ "$(env_get POSTGRES_PASSWORD)" =~ ^(|CHANGE_ME.*)$ ]] && env_set POSTGRES_PASSWORD "$(openssl rand -hex 32)"
  [[ "$(env_get OTP_HASH_SECRET)" =~ ^(|CHANGE_ME.*)$ ]] && env_set OTP_HASH_SECRET "$(openssl rand -hex 48)"
  chmod 600 "$ENV_FILE"
  ok "Settings saved to $ENV_FILE (readable by root only)"
else
  ok "Keeping existing settings"
fi
domain="$(env_get API_DOMAIN)"
db="$(env_get DATABASE_URL)"

# ---------------------------------------------------------------- 4. Checks
next "Checking DNS and database connection"
[ -n "$domain" ] || fail "API_DOMAIN is empty in $ENV_FILE."
ip="$(public_ip)"
resolved="$(resolve_a "$domain")"
if [ "$resolved" = "$ip" ]; then ok "$domain → $ip"; else
  fail "DNS: '$domain' resolves to '${resolved:-nothing}', but this server is $ip. Check API_DOMAIN in .env (for no domain use ${ip//./-}.sslip.io), then re-run."
fi
if [ -n "$db" ]; then
  # psql rejects Prisma-only URL options (connection_limit, pool_timeout, pgbouncer, schema).
  psql_url="$(printf '%s' "$db" | sed -E 's/[?&](connection_limit|pool_timeout|pgbouncer|schema)=[^&]*//g')"
  # If the removed option was first, the remaining query string starts with "&".
  [[ "$psql_url" != *"?"* ]] && psql_url="${psql_url/&/?}"
  docker run --rm postgres:16-alpine psql "$psql_url" -tAc "select 'connected to ' || current_database()" \
    && ok "Database reachable" \
    || fail "Cannot connect to the database. Check DATABASE_URL (Neon direct URL, sslmode=require)."
else
  ok "Using the built-in PostgreSQL on this server"
fi

# ---------------------------------------------------------------- 5. Build
next "Building and starting KidGuard (first time: 3–6 minutes)"
cd "$HERE"
docker compose up -d --build --remove-orphans
ok "Containers started"

# ---------------------------------------------------------------- 6. Health
next "Waiting for the API to become healthy"
for i in $(seq 1 60); do
  if docker compose exec -T api curl -fsS http://127.0.0.1:8080/health/ready >/dev/null 2>&1; then
    ok "API healthy (database migrations applied)"; break
  fi
  [ "$i" -eq 60 ] && { docker compose logs --tail=60 api; fail "API did not become healthy. Logs are above."; }
  printf '.'; sleep 3
done
for i in $(seq 1 30); do
  if curl -fsS --max-time 5 "https://$domain/health/ready" >/dev/null 2>&1; then
    ok "HTTPS works: https://$domain"; break
  fi
  [ "$i" -eq 30 ] && warn "HTTPS not ready yet (certificate may still be issuing). Check: docker compose logs caddy"
  printf '.'; sleep 4
done

# ---------------------------------------------------------------- 7. Backups
next "Backups"
if [ -z "$db" ]; then
  line="15 2 * * * $HERE/backup.sh >> /var/log/kidguard-backup.log 2>&1"
  (crontab -l 2>/dev/null | grep -vF "$HERE/backup.sh"; echo "$line") | crontab -
  ok "Nightly database backup scheduled (02:15 UTC → /var/backups/kidguard)"
else
  ok "Database is on Neon, which keeps its own backups (point-in-time restore)."
fi

cat <<EOF

${bold}${green}KidGuard API is live${off}
  URL:      https://$domain
  Health:   https://$domain/health/ready
  Logs:     cd $HERE && docker compose logs -f api
  Update:   bash $HERE/deploy.sh   (answer N to keep settings)

${bold}Next:${off}
  • Admin website (Vercel → kidguard-admin-site → Settings → Environment Variables):
      VITE_API_URL=https://$domain   then Redeploy
  • Flutter app: flutter build apk --release --dart-define=KIDGUARD_API_BASE_URL=https://$domain
  • First platform admin (only if you don't have one yet):
      read -r -s -p "Admin password: " PW; echo
      docker compose exec -e ADMIN_BOOTSTRAP_EMAIL=you@example.com -e ADMIN_BOOTSTRAP_PASSWORD="\$PW" api node dist-scripts/bootstrap-admin.js; unset PW
EOF
exit 0
}
