#!/usr/bin/env bash
set -Eeuo pipefail

echo "[GS] Initializing..."

# ========== create base directories ==========
mkdir -p /gs/{bin,secure,modules,config,docker,logs,docs}
chmod 700 /gs/secure

# ========== install dependencies ==========
apt update -y
apt install -y git curl wget jq nano unzip

# ========== install gs-cred ==========
cat >/gs/bin/gs-cred <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

GS="/gs"
SEC="$GS/secure"
MASTER="$SEC/master.key"
CRED="$SEC/credentials.enc"
TMP="$SEC/credentials.json.tmp"

if [[ ! -f "$MASTER" ]]; then
    openssl rand -hex 32 > "$MASTER"
    chmod 600 "$MASTER"
fi

MASTER_KEY=$(cat "$MASTER")
aes_enc() { openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:"$MASTER_KEY"; }
aes_dec() { openssl enc -aes-256-cbc -pbkdf2 -d -base64 -pass pass:"$MASTER_KEY"; }

load() {
  if [[ -f "$CRED" ]]; then aes_dec < "$CRED" > "$TMP"; else echo "{}" > "$TMP"; fi
}
save() {
  cat "$TMP" | aes_enc > "$CRED"
  rm -f "$TMP"
  chmod 600 "$CRED"
}

cmd="$1"; key="$2"; val="$3"

case "$cmd" in
  set)
    load
    jq --arg k "$key" --arg v "$val" '.[$k]=$v' "$TMP" > "$TMP.x"
    mv "$TMP.x" "$TMP"
    save
    echo "[cred] saved $key"
  ;;
  get)
    load
    jq -r --arg k "$key" '.[$k]' "$TMP"
    rm -f "$TMP"
  ;;
  edit)
    load
    nano "$TMP"
    save
  ;;
  *)
    echo "usage: gs-cred set <key> <value>"
    echo "       gs-cred get <key>"
    echo "       gs-cred edit"
  ;;
esac
EOF

chmod +x /gs/bin/gs-cred

# ========== install gs_install ==========
cat >/gs/bin/gs_install <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="/gs"
REPO="Glinks202/gs"

TOKEN=$(gs-cred get github_token 2>/dev/null || echo "")
if [[ -n "$TOKEN" ]]; then
  CLONE="https://$TOKEN@github.com/$REPO.git"
else
  CLONE="https://github.com/$REPO.git"
fi

if [[ ! -d "$TARGET/.git" ]]; then
  git clone "$CLONE" "$TARGET"
fi

cd "$TARGET"
bash install.sh
EOF

chmod +x /gs/bin/gs_install

# ========== install gs_push ==========
cat >/gs/bin/gs_push <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

cd /gs
TOKEN=$(gs-cred get github_token)
REPO="https://$TOKEN@github.com/Glinks202/gs.git"

git add .
git commit -m "auto update $(date '+%Y-%m-%d %H:%M:%S')" || true
git push "$REPO"
EOF

chmod +x /gs/bin/gs_push

# ========== install gs_update ==========
cat >/gs/bin/gs_update <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

cd /gs

TOKEN=$(gs-cred get github_token)
REPO="https://$TOKEN@github.com/Glinks202/gs.git"

git fetch "$REPO"
git merge --strategy-option theirs origin/main -m "auto update $(date '+%Y-%m-%d %H:%M:%S')" || true
EOF

chmod +x /gs/bin/gs_update

echo "[GS] Install complete!"
echo "Commands available:"
echo "  gs-cred    (manage encrypted credentials)"
echo "  gs_install (reinstall from GitHub)"
echo "  gs_push    (push /gs to GitHub)"
echo "  gs_update  (pull updates from GitHub)"
