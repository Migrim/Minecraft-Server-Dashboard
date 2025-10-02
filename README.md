# Minecraft Server Panel

This project is a **Flask-based Minecraft server control panel** with login, file browser, settings editor, live console, and server control (start/stop).  

---

## Download & Setup

```bash
cd /root
git clone https://github.com/Migrim/Minecraft-Server-Dashboard.git mc-panel
cd mc-panel
```

If you already have the project files locally, just upload them to your server (e.g. via SCP, rsync, FTP).

---

## ⚙️ Adjusting the Installer Script

The script (`install_mc_panel.sh`) has a few variables you may want to change before running it:

```bash
APP_DIR="/root/mc-panel"   # Directory where the app will be installed
APP_USER="mcsvc"          # System user that will run the app
APP_PORT="5003"           # Internal Flask port (do not expose directly)
MC_PORT="25565"           # Minecraft port (clients will connect here)
```

- Change **`APP_DIR`** if you want the app somewhere else (default is `/root/mc-panel`).  
- Change **`APP_USER`** if you want a different system user than `mcsvc`.  
- Change **`MC_PORT`** if you want Minecraft to run on a non-standard port.  
- Keep **`APP_PORT`** as `5003` unless you know what you’re doing — Nginx proxies to it.  

To edit:

```bash
nano install_mc_panel.sh
```

Save with **CTRL+O**, exit with **CTRL+X**.

---

## (Optional) Enable HTTPS via Let’s Encrypt

Before running the installer, define your domain and email:

```bash
export DOMAIN=yourdomain.com
export CERTBOT_EMAIL=you@example.com
```

The installer will automatically request a certificate from Let’s Encrypt and configure Nginx for HTTPS.

---

##  Run Installation

```bash
sudo bash install_mc_panel.sh
```

This will:

- Install dependencies (`python3`, `nginx`, etc.)
- Create the system user (`mcsvc`)
- Move files to `/opt/mc-panel`
- Set up a `systemd` service: **mc-panel**
- Configure Nginx for:
  - Web panel reverse proxy
  - Minecraft TCP proxy (25565)
- (Optional) Enable HTTPS if `DOMAIN` + `CERTBOT_EMAIL` are set

---

## Usage & Access

- **Web Panel:**  
  - `http://<server-ip>/`  
  - or `https://<yourdomain.com>/` (if HTTPS enabled)

- **Minecraft Server (client connection):**  
  - `<server-ip>:25565`  
  - or `yourdomain.com:25565`

- **Login (default):**  
  - Username: `admin`  
  - Password: `1234` (change on first login)

- **Upload `server.jar`:**  
  Use the `/install` page in the panel.

- **Accept EULA:**  
  Run the server once and then click the “Accept EULA” button.

- **Start Server:**  
  Click **Start** in the panel.

---

## Service Management

The panel runs as a **systemd service**:

```bash
# Status
sudo systemctl status mc-panel

# Start
sudo systemctl start mc-panel

# Stop
sudo systemctl stop mc-panel

# Restart (after changes)
sudo systemctl restart mc-panel
```

---

## Firewall

The installer configures **ufw** to allow:

- SSH (22/tcp)  
- HTTP (80/tcp)  
- HTTPS (443/tcp)  
- Minecraft (25565/tcp)  

---

## ⚠️ Requirements & Notes

- Install **Java 21+** on the server:  
  ```bash
  sudo apt install openjdk-21-jdk -y
  java -version
  ```
- Default memory allocation: `-Xmx1024M -Xms1024M` (edit in `app.py` → `start_server()`).  
- Make sure port **25565** is open on your host/ISP firewall.  
- If using a domain, set DNS A/AAAA record to your server’s IP before running Certbot.
