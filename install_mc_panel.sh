#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
APP_DIR="/opt/mc-panel"
APP_USER="mcsvc"
APP_PORT="5003"
MC_PORT="25565"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root"; exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  echo "Debian/Ubuntu required"; exit 1
fi

apt update
DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-venv python3-pip nginx ufw
if [ -n "$DOMAIN" ]; then
  DEBIAN_FRONTEND=noninteractive apt install -y certbot python3-certbot-nginx || true
fi

id -u "$APP_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR"
if [ -f "./app.py" ]; then
  rsync -a --delete --exclude venv ./ "$APP_DIR"/
fi
mkdir -p "$APP_DIR/instance/server"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install flask flask-socketio eventlet requests flask-cors gunicorn
deactivate

cat >/etc/systemd/system/mc-panel.service <<EOF
[Unit]
Description=MC Panel (Flask + SocketIO)
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$APP_DIR/venv/bin/python app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mc-panel.service

mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
cat >/etc/nginx/sites-available/mc-panel <<EOF
server {
    listen 80;
    server_name ${DOMAIN:-_};
    client_max_body_size 200m;

    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600;
    }

    location /socket.io/ {
        proxy_pass http://127.0.0.1:$APP_PORT/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600;
    }

    location /static/ {
        proxy_pass http://127.0.0.1:$APP_PORT/static/;
    }
}
EOF

ln -sf /etc/nginx/sites-available/mc-panel /etc/nginx/sites-enabled/mc-panel
if [ -e /etc/nginx/sites-enabled/default ]; then rm -f /etc/nginx/sites-enabled/default; fi

if ! grep -q "streams-enabled" /etc/nginx/nginx.conf; then
  awk '1; /http *{/ && !x {x=1; print ""} END{ }' /etc/nginx/nginx.conf >/tmp/nginx.conf.tmp
  mv /tmp/nginx.conf.tmp /etc/nginx/nginx.conf
  sed -i '1i include /etc/nginx/streams-enabled/*.conf;' /etc/nginx/nginx.conf
fi
mkdir -p /etc/nginx/streams-enabled
cat >/etc/nginx/streams-enabled/minecraft.conf <<EOF
stream {
    upstream mc_backend { server 127.0.0.1:$MC_PORT; }
    server { listen $MC_PORT; proxy_pass mc_backend; }
}
EOF

nginx -t
systemctl reload nginx

if [ -n "$DOMAIN" ] && [ -n "$CERTBOT_EMAIL" ]; then
  systemctl stop nginx || true
  systemctl start nginx || true
  certbot --nginx -n --agree-tos -m "$CERTBOT_EMAIL" -d "$DOMAIN" || true
  systemctl reload nginx || true
fi

ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow ${MC_PORT}/tcp || true
yes | ufw enable >/dev/null 2>&1 || true

LOCAL_IP=$(hostname -I | awk '{print $1}')
PUBL_IP=$(curl -fsS https://api.ipify.org || true)

echo "Panel: http://${DOMAIN:-$LOCAL_IP}"
[ -n "$DOMAIN" ] && echo "Panel HTTPS: https://$DOMAIN"
echo "Minecraft address: ${DOMAIN:-${PUBL_IP:-$LOCAL_IP}}:$MC_PORT"
