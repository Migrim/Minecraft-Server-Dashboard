# Minecraft Server Dashboard (Flask + Socket.IO)

A lightweight web dashboard to run and manage a standalone Minecraft Java server.  
Works fully locally; no external services are required.

---

## Features

- Start/stop server and view live console output
- Send commands and moderate players (op, deop, kick, ban, pardon, kill)
- Edit and save `server.properties` via UI with sane types
- Browse, download, delete, and edit files inside the server directory
- Login system with default admin and mandatory first password change
- Auto-detect Java + Minecraft version, show uptime, local/public IP
- Simple first-time flow to upload your `server.jar` from the browser

---

## Requirements

- Ubuntu 22.04/24.04 (or compatible)
- Git
- Python 3.10+ with `venv` and `pip`
- **Java 21+** runtime (OpenJDK 21 recommended)

> The dashboard **requires Java 21+** for the server process.  
> If `java -version` prints < 21, update Java or set `JAVA_CMD` to a Java 21 binary.

---

## Quick Start (Ubuntu)

```bash
# 1) System packages
sudo apt update
sudo apt install -y git python3-venv python3-pip openjdk-21-jre-headless

# 2) Clone the repository
git clone https://github.com/Migrim/Minecraft-Server-Dashboard.git
cd Minecraft-Server-Dashboard

# 3) Python virtualenv
python3 -m venv venv
source venv/bin/activate

# 4) Install Python dependencies
pip install --upgrade pip
pip install flask flask-socketio python-socketio[client] eventlet requests werkzeug flask-cors

# 5) First run (dev mode)
python app.py
```

Open the dashboard at: `http://<your-server-ip>:5003`

Default login:  
**Username:** `admin`  
**Password:** `1234`  
You’ll be asked to set a new password on first login.

---

## First-Time Server Setup

1. Visit `/install` or the **Install** page the first time you open the UI.
2. Upload your Minecraft server `server.jar`.
3. Accept the Minecraft EULA from the UI or by editing `instance/server/eula.txt` to `eula=true`.
4. Start the server from the dashboard.

Server files live in: `instance/server/`  
The dashboard creates the `instance/` folder automatically next to `app.py`.

---

## Pull Updates from GitHub

From the repository directory:

```bash
cd Minecraft-Server-Dashboard
git pull
# If dependencies changed:
source venv/bin/activate
pip install -r requirements.txt || true
pip install flask flask-socketio python-socketio[client] eventlet requests werkzeug flask-cors
```

Restart your service/process after pulling updates.

---

## Run as a Systemd Service

### 1) Create a service unit

```bash
sudo tee /etc/systemd/system/mc-dashboard.service >/dev/null <<'UNIT'
[Unit]
Description=Minecraft Server Dashboard (Flask)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%i
WorkingDirectory=/home/%i/Minecraft-Server-Dashboard
Environment=JAVA_CMD=/usr/bin/java
Environment=PYTHONUNBUFFERED=1
ExecStart=/home/%i/Minecraft-Server-Dashboard/venv/bin/python app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
```

If your username is, for example, `ubuntu`, enable and run it **templated** with your user:

```bash
# Replace 'ubuntu' with your actual Linux username
sudo systemctl enable mc-dashboard@ubuntu
sudo systemctl start mc-dashboard@ubuntu
sudo systemctl status mc-dashboard@ubuntu --no-pager
```

The app listens on port **5003**.

---

## Optional: Reverse Proxy with Nginx

```bash
sudo apt install -y nginx
sudo tee /etc/nginx/sites-available/mc-dashboard >/dev/null <<'NGINX'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5003;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX
sudo ln -s /etc/nginx/sites-available/mc-dashboard /etc/nginx/sites-enabled/mc-dashboard
sudo nginx -t && sudo systemctl reload nginx
```

Now open `http://<your-server-ip>/`.

---

## Firewall

If you access the dashboard directly (no reverse proxy):

```bash
sudo ufw allow 5003/tcp
```

If you use Nginx:

```bash
sudo ufw allow 80/tcp
```

---

## Environment Variables

- `JAVA_CMD`  
  Path to the Java 21+ binary if it’s not `/usr/bin/java`. Example:
  ```bash
  export JAVA_CMD=/usr/lib/jvm/java-21-openjdk-amd64/bin/java
  ```

---

## Default Paths

- Dashboard HTTP port: `5003`
- Instance folder: `instance/`
- Server files: `instance/server/`
- Uploaded `server.jar` filename: `server.jar`

---

## Common Tasks

- Start server: **Start** button in the UI or `GET /start`
- Stop server: **Stop** button in the UI or `GET /stop`
- Console output: auto-streamed to the dashboard
- Players list: **Players** section or `GET /get-players`
- Server status: `GET /server-status`
- Server info: `GET /server-info`
- Properties: edited via Settings page (writes to `instance/server/server.properties`)

---

## Troubleshooting

- **Java < 21 detected**  
  Install OpenJDK 21 and ensure `java -version` shows 21+.  
  Set `JAVA_CMD` if you have multiple Java versions installed.

- **Cannot bind to port 5003**  
  Make sure no other process is using 5003 or change the reverse proxy.

- **No `server.jar` found redirect**  
  Upload `server.jar` on `/install`.

- **EULA not accepted**  
  Accept via UI action or set `eula=true` in `instance/server/eula.txt`.

---

## Development

```bash
source venv/bin/activate
python app.py
```

Runs with `debug=True` and `use_reloader=False` as set in `app.py`.

---

## License

MIT (see repository)
