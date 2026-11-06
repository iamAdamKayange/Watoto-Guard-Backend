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
else
  cp "$HERE/.env.production.example" "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
ip="$(public_ip)"
mem_mb="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
is_placeholder() { [[ -z "$1" || "$1" == CHANGE_ME* || "$1" == *example.com* || "$1" == *your-connected* ]]; }
echo "  Press Enter to accept the value in [brackets]. Hidden fields don't show what you type."

if [[ "$reconfigure" =~ ^[Yy] ]]; then
  ask domain "API domain (no domain? keep the free one)" "$(v="$(env_get API_DOMAIN)"; is_placeholder "$v" && echo "${ip//./-}.sslip.io" || echo "$v")"
  env_set API_DOMAIN "$domain"
  ask acme "Email for the HTTPS certificate" "$(v="$(env_get ACME_EMAIL)"; is_placeholder "$v" || echo "$v")"
  env_set ACME_EMAIL "$acme"

  echo; echo "  ${bold}Database${off}: paste your Neon URL (Neon → Connect → turn OFF connection pooling)."
  echo "  Type 'local' to use a PostgreSQL database on this server instead."
  ask_secret v "DATABASE_URL (Enter = keep current)"
  [ "$v" = "local" ] && env_set DATABASE_URL "" || { [ -z "$v" ] || env_set DATABASE_URL "$v"; }

  echo; echo "  ${bold}Secrets${off}: copy them from Render → kidguard-api → Environment."
  ask_secret v "AUTH_TOKEN_SECRET from Render (keeps users logged in; Enter = keep/generate)"
  [ -z "$v" ] || env_set AUTH_TOKEN_SECRET "$v"
  ask_secret v "SENDLIB_API_KEY (Enter = keep)"; [ -z "$v" ] || env_set SENDLIB_API_KEY "$v"
  ask v "SENDLIB_FROM_EMAIL" "$(v="$(env_get SENDLIB_FROM_EMAIL)"; is_placeholder "$v" || echo "$v")"; [ -z "$v" ] || env_set SENDLIB_FROM_EMAIL "$v"
  ask v "GOOGLE_CLIENT_IDS (comma separated)" "$(env_get GOOGLE_CLIENT_IDS)"; env_set GOOGLE_CLIENT_IDS "$v"
  ask_secret v "GEMINI_API_KEY for KidGuard AI (Enter = keep)"; [ -z "$v" ] || env_set GEMINI_API_KEY "$v"

  echo; echo "  ${bold}Firebase (push notifications)${off}: paste the service-account JSON, then press Enter and Ctrl+D."
  echo "  (Just press Ctrl+D to keep the current one.)"
  fb="$(cat || true)"
  if [ -n "${fb//[[:space:]]/}" ]; then
    fb="$(printf '%s' "$fb" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), separators=(",",":")))')" \
      || fail "That Firebase JSON is not valid. Paste the whole file content."
    env_set FIREBASE_SERVICE_ACCOUNT_JSON "$fb"
  fi
fi

# ---- Run KidGuard AI on this server (private network) instead of Render
if [ "$(env_get AI_ASSISTANT_HOST)" != "http://ai:8000" ] || [ "$(env_get COMPOSE_PROFILES)" != "ai" ]; then
  ask v "Run KidGuard AI on this server next to the API? (Y/n)" "y"
  if [[ "$v" =~ ^[Yy] ]]; then
    env_set COMPOSE_PROFILES "ai"; env_set AI_ASSISTANT_HOST "http://ai:8000"
  fi
fi
ai_local=no; [ "$(env_get COMPOSE_PROFILES)" = "ai" ] && ai_local=yes

# ---- Fill anything missing, so an old .env picks up new keys automatically
fill_secret() { # fill_secret KEY "prompt" min_len generate(yes/no)
  local key="$1" cur; cur="$(env_get "$key")"
  if is_placeholder "$cur" || [ "${#cur}" -lt "$3" ]; then
    if [ "$4" = yes ]; then env_set "$key" "$(openssl rand -hex 48)"; ok "$key generated"
    else
      ask_secret cur "$2"
      [ "${#cur}" -ge "$3" ] || fail "$key is required (at least $3 characters)."
      env_set "$key" "$cur"
    fi
  fi
}
v="$(env_get API_DOMAIN)"; is_placeholder "$v" && env_set API_DOMAIN "${ip//./-}.sslip.io"
v="$(env_get ACME_EMAIL)"; if is_placeholder "$v"; then ask v "Email for the HTTPS certificate" ""; [ -n "$v" ] || fail "ACME_EMAIL is required."; env_set ACME_EMAIL "$v"; fi
fill_secret POSTGRES_PASSWORD "" 16 yes
fill_secret OTP_HASH_SECRET "" 32 yes
fill_secret AUTH_TOKEN_SECRET "" 32 yes
if [ "$ai_local" = yes ]; then
  # Both API and AI read this same file, so a fresh random secret always matches.
  fill_secret AI_ASSISTANT_SHARED_SECRET "" 32 yes
  fill_secret GEMINI_API_KEY "GEMINI_API_KEY (https://aistudio.google.com/apikey)" 20 no
  [ -n "$(env_get WHISPER_MODEL)" ] || env_set WHISPER_MODEL base
  [ -n "$(env_get WHISPER_CPU_THREADS)" ] || env_set WHISPER_CPU_THREADS 2
  [ -n "$(env_get GEMINI_MODEL)" ] || env_set GEMINI_MODEL gemini-3.5-flash-lite
  if [ -z "$(env_get KEEP_MODELS_LOADED)" ]; then
    [ "$mem_mb" -ge 3500 ] && env_set KEEP_MODELS_LOADED true || env_set KEEP_MODELS_LOADED false
  fi
else
  fill_secret AI_ASSISTANT_SHARED_SECRET "AI_ASSISTANT_SHARED_SECRET (same as the Render AI service)" 32 no
fi
[ -n "$(env_get CORS_ORIGINS)" ] || env_set CORS_ORIGINS "https://kidguard-admin-site.vercel.app"

# ---- Normalise the database URL (Neon direct host, SSL, pool size)
db="$(env_get DATABASE_URL)"
if [ -n "$db" ]; then
  [[ "$db" =~ ^postgres(ql)?:// ]] || fail "DATABASE_URL must start with postgresql:// (or type 'local' when asked)."
  if [[ "$db" == *"-pooler."* ]]; then
    db="${db/-pooler./.}"; warn "Switched Neon pooled host to the direct host (needed for migrations)."
  fi
  [[ "$db" == *"sslmode="* ]] || { [[ "$db" == *"?"* ]] && db="$db&sslmode=require" || db="$db?sslmode=require"; }
  [[ "$db" == *"connection_limit="* ]] || db="$db&connection_limit=10"
  env_set DATABASE_URL "$db"
fi
chmod 600 "$ENV_FILE"

# ---- Key report
echo; echo "  ${bold}Key check${off} (values are hidden):"
report() { # report KEY "what it is for" required|feature
  local v; v="$(env_get "$1")"
  if is_placeholder "$v"; then
    if [ "$3" = required ]; then printf '  %s✘%s %-30s %s\n' "$red" "$off" "$1" "MISSING – $2"; missing=1
    else printf '  %s–%s %-30s %s\n' "$yellow" "$off" "$1" "not set – $2 won't work"; fi
  else printf '  %s✔%s %-30s %s\n' "$green" "$off" "$1" "$2"; fi
}
missing=0
report API_DOMAIN "HTTPS address" required
report ACME_EMAIL "HTTPS certificate" required
if [ -n "$(env_get DATABASE_URL)" ]; then report DATABASE_URL "Neon / external database" required
else ok "DATABASE_URL                   built-in PostgreSQL on this server"; fi
report POSTGRES_PASSWORD "database container" required
report AUTH_TOKEN_SECRET "login sessions" required
report OTP_HASH_SECRET "email codes" required
report AI_ASSISTANT_HOST "API → AI address" required
report AI_ASSISTANT_SHARED_SECRET "API ↔ AI secret" required
[ "$ai_local" = yes ] && report GEMINI_API_KEY "AI answers (Gemini)" required
report SENDLIB_API_KEY "registration codes, password reset, invitations" feature
report SENDLIB_FROM_EMAIL "email sender name" feature
report FIREBASE_SERVICE_ACCOUNT_JSON "push notifications" feature
report GOOGLE_CLIENT_IDS "Google sign-in" feature
[ "$missing" -eq 0 ] || fail "Required keys are missing. Re-run and answer y to re-enter settings."
[ "$ai_local" = yes ] && ok "AI runs on this server (Whisper: $(env_get WHISPER_MODEL), keep models loaded: $(env_get KEEP_MODELS_LOADED), RAM: ${mem_mb} MB)"
ok "Settings saved to $ENV_FILE (readable by root only)"
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
next "Building and starting KidGuard (first time: 5–15 minutes with AI; later runs are quick)"
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
if [ "$ai_local" = yes ]; then
  for i in $(seq 1 60); do
    # Checked from inside the API container: proves the API can reach the AI and the secret/key are set.
    if docker compose exec -T api curl -fsS http://ai:8000/health >/dev/null 2>&1; then
      ok "KidGuard AI healthy and reachable from the API"; break
    fi
    if [ "$i" -eq 60 ]; then
      docker compose logs --tail=40 ai
      warn "AI is not healthy yet. The app still works; AI answers will fail until this is fixed (logs above)."
    fi
    printf '.'; sleep 3
  done
fi
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
  Logs:     cd $HERE && docker compose logs -f api      (AI: docker compose logs -f ai)
  Memory:   docker stats --no-stream
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
