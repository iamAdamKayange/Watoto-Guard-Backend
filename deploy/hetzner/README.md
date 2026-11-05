# Deploy KidGuard API on Hetzner

Stack: **Caddy** (automatic HTTPS) → **Node API** → **PostgreSQL 16**, plus an optional **AI assistant** container. Only ports 22/80/443 are open; the database and AI service live on a private Docker network.

## 1. Create the server
- Hetzner Cloud → Ubuntu 24.04, location **Helsinki/Falkenstein/Nuremberg**.
- Size: **CPX21** (3 vCPU / 4 GB) for API + DB. If you enable the AI voice service, use **CPX31** (4 vCPU / 8 GB).
- Add your SSH key when creating the server, and enable Hetzner **Backups** (snapshots) as a second safety net.
- DNS: create an `A` record (and `AAAA` for IPv6) e.g. `api.yourdomain.com` → server IP.

## 2. Harden the server (once, as root)
First (recommended) add an SSH key from your Windows PC, so password logins can be switched off:
```powershell
ssh-keygen -t ed25519
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh root@SERVER_IP "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```
Then on the server:
```bash
git clone https://github.com/iamAdamKayange/Watoto-Guard-Backend.git /opt/kidguard/backend
bash /opt/kidguard/backend/deploy/hetzner/server-setup.sh
reboot
```
This installs Docker, enables the UFW firewall (22/80/443 only), fail2ban, automatic security updates and swap. Password SSH login is disabled **only if** an SSH key is installed, so you cannot lock yourself out.

## 3. Deploy
```bash
ssh root@SERVER_IP
cd /opt/kidguard/backend && git pull
cd deploy/hetzner
cp .env.production.example .env
nano .env            # fill API_DOMAIN, secrets (openssl rand -base64 48)
docker compose up -d --build                 # API + DB + HTTPS
docker compose --profile ai up -d --build    # optional: AI / Guardian Voice
```
`FIREBASE_SERVICE_ACCOUNT_JSON` must be on **one line** in `.env` (e.g. `jq -c . service-account.json`).

Check: `curl https://api.yourdomain.com/health/ready` → `{"status":"ok","database":"ok"}`.

Then create the platform admin once (the password is read from your terminal, not stored in shell history):
```bash
read -r -s -p "Admin password: " PW && echo
docker compose exec -e ADMIN_BOOTSTRAP_EMAIL=you@example.com -e ADMIN_BOOTSTRAP_PASSWORD="$PW" api node dist-scripts/bootstrap-admin.js
unset PW
```

## 4. Point the apps to the new API
- Flutter: `flutter build apk --release --dart-define=KIDGUARD_API_BASE_URL=https://api.yourdomain.com`
- Admin website (Vercel project `kidguard-admin-site`): set `VITE_API_URL=https://<API_DOMAIN>` in Vercel → Settings → Environment Variables, then redeploy. Its origin `https://kidguard-admin-site.vercel.app` is already allowed by the API.

## 5. Move data from Render (if migrating)
```bash
# On a machine with access to the old Render DB:
pg_dump "$RENDER_DATABASE_URL" --format=custom --no-owner > render.dump
scp render.dump kidguard@SERVER_IP:/tmp/
# On the server (stack stopped except db):
docker compose stop api
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' < /tmp/render.dump
docker compose start api   # applies any newer migrations automatically
```

## 6. Backups & updates
- Nightly DB dumps: `crontab -e` → `15 2 * * * /opt/kidguard/backend/deploy/hetzner/backup.sh >> /var/log/kidguard-backup.log 2>&1`. Copy `/var/backups/kidguard` off the server (Hetzner Storage Box).
- Update: `cd /opt/kidguard/backend && git pull && cd deploy/hetzner && docker compose up -d --build` (migrations run automatically on start; zero manual steps).
- Logs: `docker compose logs -f api`.

## Security notes
- All sessions can be revoked per user with `POST /api/auth/logout-all`; password reset revokes them automatically.
- Login, OTP, invitation, pairing and public form endpoints are rate-limited per IP and per account.
- Rotate any secret that was ever committed or shared in chat before going live.
