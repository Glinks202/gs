#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# GS ROOT PATH
# ============================================================
BASE="$(cd "$(dirname "$0")" && pwd)"
export GS_ROOT="$BASE"
export GS_SEC="$GS_ROOT/secure"
export GS_CFG="$GS_ROOT/config"
export GS_MOD="$GS_ROOT/modules"

mkdir -p "$GS_SEC" "$GS_CFG" "$GS_ROOT/logs" "$GS_ROOT/docker" \
"$GS_ROOT/mount/mac" "$GS_ROOT/bin" \
"$GS_MOD/init" "$GS_MOD/docker" "$GS_MOD/npm" "$GS_MOD/cloudmac" \
"$GS_MOD/backup" "$GS_MOD/logs" "$GS_MOD/watchdog" "$GS_MOD/report"

chmod 700 "$GS_SEC"

# ============================================================
# LOG FUNCTIONS
# ============================================================
gs_log(){ echo -e "\033[1;32m[GS]\033[0m $*"; }
gs_err(){ echo -e "\033[1;31m[ERR]\033[0m $*"; exit 1; }

# ============================================================
# READ CONFIG
# ============================================================
export MAC_USER=$(jq -r '.cloudmac.user' "$GS_CFG/system.json" 2>/dev/null || echo "Hulin")
export MAC_IP=$(jq -r '.cloudmac.ip' "$GS_CFG/system.json" 2>/dev/null || echo "192.111.137.81")
export API_DOMAIN=$(jq -r '.api_domain' "$GS_CFG/system.json" 2>/dev/null || echo "api.hulin.pro")

export MAC_PASS=$(cat "$GS_SEC/mac_pass" 2>/dev/null || echo "")

ssh_cm(){ ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=15 -o ServerAliveCountMax=5 "$MAC_USER@$MAC_IP" "$@"; }
aes_enc(){ echo -n "$1" | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:"$2"; }

kill_port(){
    for pid in $(ss -tulpn | grep ":$1 " | awk '{print $NF}' | sed 's/.*pid=//;s/,.*//'); do
        kill -9 "$pid" 2>/dev/null || true
    done
}

# ============================================================
# 0. INIT ENV
# ============================================================
gs_log "Initializing environment..."

[[ ! -f "$GS_SEC/master_key" ]] && openssl rand -hex 32 > "$GS_SEC/master_key"
MASTER_KEY=$(cat "$GS_SEC/master_key")

apt update -y >/dev/null
apt install -y jq curl wget git zip unzip sshpass sshfs rsync htop \
python3 python3-pip python3-venv ca-certificates gnupg lsb-release \
ufw fail2ban tesseract-ocr tesseract-ocr-chi-sim >/dev/null

# TIMEZONE & SYSCTL
timedatectl set-timezone America/New_York || true
echo "fs.file-max=1000000" >> /etc/sysctl.conf
echo "vm.swappiness=10" >> /etc/sysctl.conf
sysctl -p >/dev/null

# PYTHON VENV
mkdir -p "$GS_ROOT/venv"
python3 -m venv "$GS_ROOT/venv"
"$GS_ROOT/venv/bin/pip" install --upgrade pip >/dev/null


# ============================================================
# 1. SECURITY
# ============================================================
gs_log "Applying security settings..."

ufw default deny incoming
ufw default allow outgoing

ALLOW_PORTS=$(jq -r '.security.ufw_allow[]' "$GS_CFG/system.json" 2>/dev/null || echo -e "22\n80\n443")
for p in $ALLOW_PORTS; do ufw allow $p; done
ufw --force enable

systemctl enable fail2ban --now >/dev/null


# ============================================================
# 2. DOCKER CORE
# ============================================================
gs_log "Installing Docker core..."

if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor \
      -o /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

  apt update >/dev/null
  apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
  systemctl enable docker --now
fi

docker network inspect gs-net >/dev/null 2>&1 || docker network create gs-net


# ============================================================
# 3. PORTAINER
# ============================================================
gs_log "Deploying Portainer..."

docker rm -f portainer >/dev/null 2>&1 || true
docker volume create portainer_data >/dev/null

docker run -d --name portainer --restart always \
  -p 9001:9000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest


# ============================================================
# 4. DATABASE MARIADB + REDIS
# ============================================================
gs_log "Deploying MariaDB + Redis..."

docker rm -f mariadb redis >/dev/null 2>&1 || true
mkdir -p "$GS_ROOT/docker/mariadb" "$GS_ROOT/docker/redis"

docker run -d --name mariadb --restart always --network gs-net \
  -v $GS_ROOT/docker/mariadb:/var/lib/mysql \
  -e MYSQL_ROOT_PASSWORD="gs_root_pw" \
  mariadb:11

docker run -d --name redis --restart always --network gs-net \
  -v $GS_ROOT/docker/redis:/data redis:7


# ============================================================
# 5. NPM
# ============================================================
gs_log "Deploying Nginx Proxy Manager..."

kill_port 80; kill_port 81; kill_port 443
docker rm -f npm >/dev/null 2>&1 || true

mkdir -p "$GS_ROOT/docker/npm/data" "$GS_ROOT/docker/npm/letsencrypt"

docker run -d --name npm --restart always --network gs-net \
  -p 80:80 -p 81:81 -p 443:443 \
  -v $GS_ROOT/docker/npm/data:/data \
  -v $GS_ROOT/docker/npm/letsencrypt:/etc/letsencrypt \
  jc21/nginx-proxy-manager:latest

until curl -s http://localhost:81/api/status | grep -q running; do sleep 3; done


# NPM LOGIN
gs_log "Logging in NPM..."

NPM_USER=$(jq -r '.npm.default_user' "$GS_CFG/system.json")
NPM_PASS=$(jq -r '.npm.default_pass' "$GS_CFG/system.json")

TOKEN=$(curl -s -X POST http://localhost:81/api/tokens \
  -H "Content-Type: application/json" \
  -d "{\"identity\":\"$NPM_USER\",\"secret\":\"$NPM_PASS\"}" | jq -r '.token')

[[ -z "$TOKEN" || "$TOKEN" == "null" ]] && gs_err "NPM login failed"
echo "{\"npm_token\":\"$TOKEN\"}" > "$GS_CFG/npm_token.json"


# ============================================================
# 6. PROXY + SSL
# ============================================================
gs_log "Configuring proxy + ssl..."

curl -s -X POST "http://localhost:81/api/nginx/proxy-hosts" \
-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
-d "{\"domain_names\":[\"$API_DOMAIN\"],\"forward_scheme\":\"http\",\"forward_host\":\"$MAC_IP\",\"forward_port\":5000,\"certificate_id\":0}" >/dev/null

HOST_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:81/api/nginx/proxy-hosts \
    | jq -r ".[] | select(.domain_names[] == \"$API_DOMAIN\") | .id")

curl -s -X PUT "http://localhost:81/api/nginx/proxy-hosts/$HOST_ID" \
-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
-d "{\"certificate_id\":1,\"ssl_forced\":true,\"lets_encrypt_agree\":true}" >/dev/null

echo "{\"rate\":\"30r/m\",\"burst\":20}" > "$GS_CFG/api_limit.json"


# ============================================================
# 7. DEPLOY SERVICES (NC / OO / WP / Cockpit / noVNC)
# ============================================================
gs_log "Deploying all services..."

mkdir -p $GS_ROOT/docker/{nextcloud,onlyoffice,wordpress,novnc,cockpit}

docker rm -f nextcloud onlyoffice wordpress cockpit novnc >/dev/null 2>&1 || true

docker run -d --name nextcloud --restart always --network gs-net \
  -v $GS_ROOT/docker/nextcloud:/var/www/html nextcloud:27

docker run -d --name onlyoffice --restart always --network gs-net \
  -v $GS_ROOT/docker/onlyoffice:/var/www/onlyoffice/Data \
  onlyoffice/documentserver:latest

docker run -d --name wordpress --restart always --network gs-net \
  -p 8080:80 \
  -e WORDPRESS_DB_HOST="mariadb" \
  -e WORDPRESS_DB_USER="root" \
  -e WORDPRESS_DB_PASSWORD="gs_root_pw" \
  -e WORDPRESS_DB_NAME="wp" \
  -v $GS_ROOT/docker/wordpress:/var/www/html \
  wordpress:php8.2-apache

docker run -d --name cockpit --restart always --privileged --pid=host \
  -p 9090:9090 hellt/cockpit:latest

docker run -d --name novnc --restart always \
  -p 6080:6080 \
  -e VNC_PASSWD="admin" \
  dorowu/ubuntu-desktop-lxde-vnc


# ============================================================
# 8. OPTIMIZE WP + DB
# ============================================================
gs_log "Optimizing WordPress + MariaDB..."
docker exec wordpress bash -c "a2enmod rewrite; service apache2 restart" >/dev/null || true
docker exec mariadb bash -c "mysql -uroot -pgs_root_pw -e 'SET GLOBAL innodb_buffer_pool_size=256*1024*1024; SET GLOBAL max_connections=200;'" >/dev/null || true


# ============================================================
# 9. CLOUDMAC SSHFS
# ============================================================
gs_log "Mounting CloudMac..."

sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=5,StrictHostKeyChecking=no \
  "$MAC_USER@$MAC_IP:/Users/$MAC_USER" \
  "$GS_ROOT/mount/mac" \
  >> "$GS_ROOT/logs/sshfs_mount.log" 2>&1 || true


# ============================================================
# 10. WATCHDOG SYSTEM (sshfs, service, proxy, health)
# ============================================================

gs_log "Creating watchdog modules..."

# SSHFS WATCH
cat > "$GS_ROOT/bin/sshfs_watch.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
M="$GS_ROOT/mount/mac"
U="$MAC_USER"
I="$MAC_IP"

while true; do
    if ! mount | grep -q "\$M"; then
        sshfs -o reconnect,ServerAliveInterval=10,ServerAliveCountMax=5,StrictHostKeyChecking=no \
            "\$U@\$I:/Users/\$U" "\$M"
    fi
    sleep 8
done
EOF
chmod +x "$GS_ROOT/bin/sshfs_watch.sh"
nohup "$GS_ROOT/bin/sshfs_watch.sh" >/dev/null 2>&1 &

# SERVICE WATCH
cat > "$GS_ROOT/bin/service_watch.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
SERV="npm mariadb redis wordpress nextcloud onlyoffice cockpit novnc"

while true; do
    for s in \$SERV; do
        docker ps --format "{{.Names}}" | grep -qx "\$s" || docker restart "\$s"
    done
    sleep 10
done
EOF
chmod +x "$GS_ROOT/bin/service_watch.sh"
nohup "$GS_ROOT/bin/service_watch.sh" >/dev/null 2>&1 &

# PROXY WATCH
cat > "$GS_ROOT/bin/proxy_watch.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
DOMAIN="$API_DOMAIN"

while true; do
    C=\$(curl -sk -o /dev/null -w "%{http_code}" "https://\$DOMAIN")
    [[ "\$C" == "200" ]] || docker restart npm
    sleep 20
done
EOF
chmod +x "$GS_ROOT/bin/proxy_watch.sh"
nohup "$GS_ROOT/bin/proxy_watch.sh" >/dev/null 2>&1 &

# HEALTH WATCH
cat > "$GS_ROOT/bin/health_watch.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN="$API_DOMAIN"

while true; do
    C=\$(curl -sk -o /dev/null -w "%{http_code}" "https://\$DOMAIN")
    if [[ "\$C" != "200" ]]; then
        ssh $MAC_USER@$MAC_IP \
            "launchctl unload ~/Library/LaunchAgents/com.gs.macapi.plist >/dev/null 2>&1; \
             launchctl load   ~/Library/LaunchAgents/com.gs.macapi.plist" >/dev/null 2>&1
    fi
    sleep 15
done
EOF
chmod +x "$GS_ROOT/bin/health_watch.sh"
nohup "$GS_ROOT/bin/health_watch.sh" >/dev/null 2>&1 &


# ============================================================
# 11. BACKUP + LOGROTATE
# ============================================================

gs_log "Enabling backup + log rotation..."

mkdir -p "$GS_ROOT/backup/full" "$GS_ROOT/backup/daily"

# FULL BACKUP
cat > "$GS_ROOT/bin/backup_full.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
TS=\$(date +%Y%m%d_%H%M)
DST="$GS_ROOT/backup/full/full_\$TS.tar.gz"
tar -czf "\$DST" "$GS_ROOT/docker" "$GS_ROOT/config" "$GS_ROOT/secure" "$GS_ROOT/mount/mac/gs-share"
EOF
chmod +x "$GS_ROOT/bin/backup_full.sh"

# DAILY BACKUP
cat > "$GS_ROOT/bin/backup_daily.sh" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
TS=\$(date +%Y%m%d)
DST="$GS_ROOT/backup/daily/daily_\$TS.tar.gz"
tar -czf "\$DST" "$GS_ROOT/config" "$GS_ROOT/mount/mac/gs-share"
EOF
chmod +x "$GS_ROOT/bin/backup_daily.sh"

# LOG ROTATE
cat > "$GS_ROOT/bin/log_rotate.sh" <<EOF
#!/usr/bin/env bash
find "$GS_ROOT/logs" -type f -size +20M -delete
find "$GS_ROOT/backup/daily" -type f -mtime +14 -delete
find "$GS_ROOT/backup/full" -type f -mtime +30 -delete
EOF
chmod +x "$GS_ROOT/bin/log_rotate.sh"

# CRONJOBS
(crontab -l 2>/dev/null; echo "0 3 * * * $GS_ROOT/bin/backup_daily.sh >/dev/null") | crontab -
(crontab -l 2>/dev/null; echo "0 4 * * 0 $GS_ROOT/bin/backup_full.sh >/dev/null") | crontab -
(crontab -l 2>/dev/null; echo "*/10 * * * * $GS_ROOT/bin/log_rotate.sh >/dev/null") | crontab -


# ============================================================
# 12. FINAL REPORT
# ============================================================

gs_log "Generating final system report..."

REPORT="$GS_ROOT/logs/final_report.txt"

{
    echo "==================== GS SYSTEM REPORT ===================="
    echo "Generated: $(date)"
    echo
    echo "----------VPS----------"
    echo "Hostname: $(hostname)"
    echo "IP: $(hostname -I | awk '{print $1}')"
    echo
    echo "----------CloudMac----------"
    echo "User: $MAC_USER"
    echo "IP:   $MAC_IP"
    echo "Mounted: $(mount | grep -q "$GS_ROOT/mount/mac" && echo yes || echo no)"
    echo
    echo "----------API----------"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$API_DOMAIN")
    echo "Domain: $API_DOMAIN"
    echo "Status: HTTP $CODE"
    echo
    echo "----------Docker----------"
    docker ps --format " - {{.Names}} : {{.Status}}"
    echo
    echo "----------------------------------------------------------"
    echo "GS SYSTEM STATUS: ONLINE"
    echo "----------------------------------------------------------"
} > "$REPORT"

echo "GS-INSTALL-COMPLETE" > "$GS_ROOT/INSTALL_DONE"


# ============================================================
# SUCCESS BANNER
# ============================================================

echo -e "\n\033[1;32m"
echo "██████   ██████      ███    ███   ███████ "
echo "██   ██ ██    ██     ████  ████   ██      "
echo "██████  ██    ██     ██ ████ ██   █████   "
echo "██      ██    ██     ██  ██  ██   ██      "
echo "██       ██████      ██      ██   ███████ "
echo
echo "   G S   S Y S T E M   D E P L O Y E D"
echo "   -----------------------------------"
echo "   All modules initialized successfully."
echo -e "\033[0m\n"

gs_log "GS ALL SYSTEMS ONLINE"
