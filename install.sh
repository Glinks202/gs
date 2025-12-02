#!/usr/bin/env bash
set -Eeuo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
export GS_ROOT="$BASE"
export GS_SEC="$GS_ROOT/secure"
export GS_CFG="$GS_ROOT/config"
export GS_MOD="$GS_ROOT/modules"

# =========================
# LOG
# =========================
log(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERR]\033[0m $*"; exit 1; }

# =========================
# GLOBAL
# =========================
export MAC_USER=$(jq -r '.cloudmac.user' "$GS_CFG/system.json" 2>/dev/null || echo "Hulin")
export MAC_IP=$(jq -r '.cloudmac.ip' "$GS_CFG/system.json" 2>/dev/null || echo "192.111.137.81")
export MAC_PASS=$(cat "$GS_SEC/mac_pass" 2>/dev/null || echo "")

ssh_cm(){ ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=15 -o ServerAliveCountMax=5 "$MAC_USER@$MAC_IP" "$@"; }
aes_enc(){ echo -n "$1" | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:"$2"; }

kill_port(){ P=$(ss -tulpn|grep ":$1 "|awk '{print $NF}'|sed 's/.*pid=$begin:math:text$\[0\-9\]\*$end:math:text$.*/\1/');for pid in $P;do kill -9 "$pid" 2>/dev/null||true;done; }

mkdir -p "$GS_SEC" "$GS_CFG" "$GS_ROOT/docker" "$GS_ROOT/logs" "$GS_ROOT/docs" "$GS_MOD" \
"$GS_MOD/init" "$GS_MOD/docker" "$GS_MOD/npm" "$GS_MOD/cloudmac" "$GS_MOD/backup" \
"$GS_MOD/logs" "$GS_MOD/watchdog" "$GS_MOD/report"
chmod 700 "$GS_SEC"

# =========================
# INIT ENV
# =========================
log "[0] init_env"
[[ ! -f "$GS_SEC/master_key" ]] && openssl rand -hex 32 > "$GS_SEC/master_key"
MASTER_KEY=$(cat "$GS_SEC/master_key")

# =========================
# SECURITY
# =========================
log "[1] security"
apt update -y
apt install -y ufw fail2ban >/dev/null

ufw default deny incoming
ufw default allow outgoing
for p in $(jq -r '.security.ufw_allow[]' "$GS_CFG/system.json");do ufw allow $p;done
ufw --force enable

systemctl enable fail2ban --now >/dev/null

sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config || true
systemctl restart sshd || true

# =========================
# BASE
# =========================
log "[2] base"
apt install -y curl wget jq git zip unzip sshpass sshfs rsync htop pwgen \
python3 python3-pip python3-venv ca-certificates gnupg lsb-release tesseract-ocr tesseract-ocr-chi-sim >/dev/null 2>&1

timedatectl set-timezone America/New_York || true
echo "fs.file-max=1000000" >> /etc/sysctl.conf
echo "vm.swappiness=10" >> /etc/sysctl.conf
sysctl -p >/dev/null

# PYTHON VENV
mkdir -p "$GS_ROOT/venv"
python3 -m venv "$GS_ROOT/venv"
"$GS_ROOT/venv/bin/pip" install --upgrade pip >/dev/null

# =========================
# DOCKER CORE
# =========================
log "[3] docker_core"
if ! command -v docker >/dev/null;then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg|gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable docker --now
fi

docker network inspect gs-net >/dev/null 2>&1 || docker network create gs-net

# =========================
# PORTAINER
# =========================
log "[4] portainer"
docker rm -f portainer >/dev/null 2>&1||true
docker volume create portainer_data >/dev/null
docker run -d --name portainer --restart always -p 9001:9000 \
  -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data \
  portainer/portainer-ce:latest

# =========================
# DATABASE
# =========================
log "[5] database"
docker rm -f mariadb redis >/dev/null 2>&1||true
mkdir -p "$GS_ROOT/docker/mariadb" "$GS_ROOT/docker/redis"

docker run -d --name mariadb --restart always --network gs-net \
  -v $GS_ROOT/docker/mariadb:/var/lib/mysql \
  -e MYSQL_ROOT_PASSWORD="gs_root_pw" mariadb:11

docker run -d --name redis --restart always --network gs-net \
  -v $GS_ROOT/docker/redis:/data redis:7

# =========================
# NPM
# =========================
log "[6] npm"
kill_port 80;kill_port 81;kill_port 443
docker rm -f npm >/dev/null 2>&1||true
mkdir -p "$GS_ROOT/docker/npm/data" "$GS_ROOT/docker/npm/letsencrypt"

docker run -d --name npm --restart always --network gs-net \
  -p 80:80 -p 81:81 -p 443:443 \
  -v $GS_ROOT/docker/npm/data:/data \
  -v $GS_ROOT/docker/npm/letsencrypt:/etc/letsencrypt \
  jc21/nginx-proxy-manager:latest

# Wait for NPM
until curl -s http://localhost:81/api/status|grep -q running;do sleep 3;done

log "[6.1] npm login"
user=$(jq -r '.npm.default_user' "$GS_CFG/system.json")
pass=$(jq -r '.npm.default_pass' "$GS_CFG/system.json")
TOKEN=$(curl -s -X POST http://localhost:81/api/tokens \
  -H "Content-Type: application/json" \
  -d "{\"identity\":\"$user\",\"secret\":\"$pass\"}" |jq -r '.token')
[[ -z "$TOKEN" || "$TOKEN"=="null" ]] && err "npm login failed"
echo "{\"npm_token\":\"$TOKEN\"}" > "$GS_CFG/npm_token.json"

# =========================
# API PROXY + SSL
# =========================
log "[7] proxy + ssl"
domain=$(jq -r '.api_domain' "$GS_CFG/system.json")

curl -s -X POST "http://localhost:81/api/nginx/proxy-hosts" \
-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
-d "{\"domain_names\":[\"$domain\"],\"forward_scheme\":\"http\",\"forward_host\":\"$MAC_IP\",\"forward_port\":5000,\"certificate_id\":0}" >/dev/null

host_id=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:81/api/nginx/proxy-hosts \
  | jq -r ".[]|select(.domain_names[]==\"$domain\")|.id")

curl -s -X PUT "http://localhost:81/api/nginx/proxy-hosts/$host_id" \
-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
-d "{\"certificate_id\":1,\"ssl_forced\":true,\"lets_encrypt_agree\":true}" >/dev/null

echo "{\"rate\":\"30r/m\",\"burst\":20}" > "$GS_CFG/api_limit.json"

# =========================
# DEPLOY SERVICES
# =========================
log "[8] deploy services"

mkdir -p $GS_ROOT/docker/{nextcloud,onlyoffice,wordpress,novnc,cockpit}

docker rm -f nextcloud >/dev/null 2>&1||true
docker run -d --name nextcloud --restart always --network gs-net \
  -v $GS_ROOT/docker/nextcloud:/var/www/html nextcloud:27

docker rm -f onlyoffice >/dev/null 2>&1||true
docker run -d --name onlyoffice --restart always --network gs-net \
  -v $GS_ROOT/docker/onlyoffice:/var/www/onlyoffice/Data \
  onlyoffice/documentserver:latest

docker rm -f wordpress >/dev/null 2>&1||true
docker run -d --name wordpress --restart always --network gs-net \
  -p 8080:80 \
  -e WORDPRESS_DB_HOST="mariadb" \
  -e WORDPRESS_DB_USER="root" \
  -e WORDPRESS_DB_PASSWORD="gs_root_pw" \
  -e WORDPRESS_DB_NAME="wp" \
  -v $GS_ROOT/docker/wordpress:/var/www/html \
  wordpress:php8.2-apache

docker rm -f cockpit >/dev/null 2>&1||true
docker run -d --name cockpit --restart always --privileged --pid=host \
  -p 9090:9090 hellt/cockpit:latest

docker rm -f novnc >/dev/null 2>&1||true
docker run -d --name novnc --restart always -p 6080:6080 \
  -e VNC_PASSWD="admin" dorowu/ubuntu-desktop-lxde-vnc

# =========================
# OPTIMIZE WP / DB
# =========================
log "[9] optimize"
docker exec wordpress bash -c "a2enmod rewrite;service apache2 restart" >/dev/null 2>&1||true
docker exec mariadb bash -c "mysql -uroot -pgs_root_pw -e 'SET GLOBAL innodb_buffer_pool_size=256*1024*1024;SET GLOBAL max_connections=200;'" >/dev/null 2>&1||true

# =========================
# CLOUDMAC MOUNT
# =========================
log "[10] cloudmac mount"
mkdir -p "$GS_ROOT/mount/mac"
sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=5,StrictHostKeyChecking=no \
  "$MAC_USER@$MAC_IP:/Users/$MAC_USER" \
  "$GS_ROOT/mount/mac" >> "$GS_ROOT/logs/sshfs_mount.log" 2>&1 || true

# WATCHDOG
log "[11] watchdog"

# sshfs_watch
cat > "$GS_ROOT/bin/sshfs_watch.sh" <<EOF
#!/usr/bin/env bash
M="$GS_ROOT/mount/mac"
while true;do
  if ! mount|grep -q "\$M";then
    sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=5,StrictHostKeyChecking=no \
    $MAC_USER@$MAC_IP:/Users/$MAC_USER "\$M"
  fi
  sleep 8
done
EOF
chmod +x "$GS_ROOT/bin/sshfs_watch.sh"
nohup "$GS_ROOT/bin/sshfs_watch.sh" >/dev/null 2>&1 &

# service_watch
cat > "$GS_ROOT/bin/service_watch.sh" <<EOF
#!/usr/bin/env bash
S="npm mariadb redis wordpress nextcloud onlyoffice cockpit novnc"
while true;do
  for i in \$S;do docker ps|grep -q "\$i"||docker restart \$i;done
  sleep 15
done
EOF
chmod +x "$GS_ROOT/bin/service_watch.sh"
nohup "$GS_ROOT/bin/service_watch.sh" >/dev/null 2>&1 &

# proxy_watch
cat > "$GS_ROOT/bin/proxy_watch.sh" <<EOF
#!/usr/bin/env bash
while true;do
  c=\$(curl -sk -o /dev/null -w "%{http_code}" "https://$domain")
  [[ "\$c"=="200" ]]||docker restart npm
  sleep 20
done
EOF
chmod +x "$GS_ROOT/bin/proxy_watch.sh"
nohup "$GS_ROOT/bin/proxy_watch.sh" >/dev/null 2>&1 &

# =========================
# REPORT
# =========================
log "[12] report"

rpt="$GS_ROOT/logs/final_report.txt"
{
  echo "===== GS SYSTEM REPORT ====="
  echo "Time: $(date)"
  echo "Domain: $domain"
  echo "Services:"
  docker ps --format " - {{.Names}} : {{.Status}}"
} > "$rpt"

log "系统安装完成"
echo -e "\n\033[1;32m🎉 GS ALL SYSTEMS ONLINE\033[0m"
