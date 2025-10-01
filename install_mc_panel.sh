#!/usr/bin/env bash
set -euo pipefail
trap 'ec=$?; echo "ERROR $ec on line $LINENO"; exit $ec' ERR

DOMAIN="${DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
APP_DIR="$(readlink -f "${APP_DIR:-$PWD}")"
APP_PORT="${APP_PORT:-5003}"
MC_PORT="${MC_PORT:-25565}"
WANT_NGINX_STREAM="${WANT_NGINX_STREAM:-0}"
MC_BACKEND_PORT="${MC_BACKEND_PORT:-25566}"

if [ "$(id -u)" -ne 0 ]; then echo "run as root"; exit 1; fi
if ! command -v apt >/dev/null 2>&1; then echo "Debian/Ubuntu required"; exit 1; fi

apt update
DEBIAN_FRONTEND=noninteractive apt install -y python3 python3-venv python3-pip nginx-full ufw rsync curl git
if [ -n "$DOMAIN" ]; then DEBIAN_FRONTEND=noninteractive apt install -y certbot python3-certbot-nginx || true; fi

mkdir -p "$APP_DIR/instance/server" "$APP_DIR/uploads" "$APP_DIR/server-files"
cd "$APP_DIR"

python3 -m venv venv
"$APP_DIR/venv/bin/pip" install --upgrade pip setuptools wheel
"$APP_DIR/venv/bin/pip" install flask flask-socketio eventlet requests flask-cors gunicorn
"$APP_DIR/venv/bin/python" - <<'PY'
import flask, flask_socketio, eventlet, flask_cors
print("ok")
PY

chown -R root:root "$APP_DIR"
find "$APP_DIR" -type d -exec chmod 0775 {} \;
find "$APP_DIR" -type f -not -path "$APP_DIR/venv/bin/*" -exec chmod 0664 {} \;
chmod 0755 "$APP_DIR/venv/bin" "$APP_DIR/venv/bin/"*

mkdir -p /opt
if [ -e /opt/mc-panel ] && [ ! -L /opt/mc-panel ]; then rm -rf /opt/mc-panel; fi
ln -sfn "$APP_DIR" /opt/mc-panel
chown -h root:root /opt/mc-panel

APP_MODULE="app:app"
[ -f "$APP_DIR/Server.py" ] && APP_MODULE="Server:app"

cat >/etc/systemd/system/mc-panel.service <<EOF
[Unit]
Description=MC Panel (Flask + SocketIO)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
Environment=INSTANCE_PATH=$APP_DIR/instance
UMask=007
ExecStartPre=/usr/bin/install -d -o root -g root -m 0775 $APP_DIR/instance $APP_DIR/instance/server $APP_DIR/uploads $APP_DIR/server-files
ExecStart=$APP_DIR/venv/bin/gunicorn -k eventlet -w 1 -b 127.0.0.1:$APP_PORT $APP_MODULE
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mc-panel.service || true

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
rm -f /etc/nginx/sites-enabled/default || true

if [ "$WANT_NGINX_STREAM" = "1" ]; then
  mkdir -p /etc/nginx/modules-enabled
  tee /etc/nginx/modules-enabled/50-mod-stream.conf >/dev/null <<'EOF'
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
EOF
  grep -q 'include /etc/nginx/stream\.conf;' /etc/nginx/nginx.conf || sed -i '1i include /etc/nginx/stream.conf;' /etc/nginx/nginx.conf
  cat >/etc/nginx/stream.conf <<EOF
stream {
    server {
        listen $MC_PORT;
        proxy_pass 127.0.0.1:$MC_BACKEND_PORT;
    }
}
EOF
else
  sed -i '/include \/etc\/nginx\/stream\.conf;/d' /etc/nginx/nginx.conf || true
  rm -f /etc/nginx/stream.conf || true
fi

if ! nginx -t; then nginx -T | sed -n '1,200p'; exit 1; fi
systemctl reload nginx || systemctl restart nginx || true

if [ -n "$DOMAIN" ] && [ -n "$CERTBOT_EMAIL" ]; then
  systemctl start nginx || true
  certbot --nginx -n --agree-tos -m "$CERTBOT_EMAIL" -d "$DOMAIN" || true
  systemctl reload nginx || systemctl restart nginx || true
fi

ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw allow ${MC_PORT}/tcp || true
yes | ufw enable >/dev/null 2>&1 || true

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
PUBL_IP=$(curl -fsS https://api.ipify.org || true)
echo "Install dir: $APP_DIR"
echo "Legacy path: /opt/mc-panel -> $APP_DIR"
echo "Panel: http://${DOMAIN:-$LOCAL_IP}"
[ -n "$DOMAIN" ] && echo "Panel HTTPS: https://$DOMAIN"
echo "Minecraft address: ${DOMAIN:-${PUBL_IP:-$LOCAL_IP}}:$MC_PORT"
ss -ltnp | grep ":$MC_PORT " || true
ufw status | grep -E "$MC_PORT" || true