# Minecraft Server Panel + Reverse Proxy

This project is a **Flask-based Minecraft server control panel** with built-in login, file browser, settings editor, console output, and server start/stop functionality.  
An install script is included that:

- Sets up Python dependencies in a virtualenv
- Installs and configures **systemd** to run the panel automatically
- Configures **Nginx** as a reverse proxy for the panel (with optional HTTPS via Let’s Encrypt)
- Configures **Nginx TCP stream proxy** so Minecraft (port 25565) is accessible externally

---

## 🚀 Installation

### 1. Copy files to your server
Upload the project (including `app.py`, templates, and static folders) to your server.  
For example, place it in `/root/mc-panel/`.

### 2. Run the installer
From inside the project folder:

```bash
sudo bash install_mc_panel.sh
```

The script will:

- Install required packages (`python3`, `nginx`, etc.)
- Create a service user (`mcsvc`)
- Set up the app in `/opt/mc-panel`
- Configure Nginx for the web panel and Minecraft reverse proxy
- Enable and start the systemd service (`mc-panel.service`)

### 3. (Optional) Enable HTTPS
Before running the script, export your domain and email:

```bash
export DOMAIN=yourdomain.com
export CERTBOT_EMAIL=you@example.com
sudo bash install_mc_panel.sh
```

The script will request a Let’s Encrypt SSL certificate and configure HTTPS automatically.

---

## 🔧 Usage

- **Web Panel:**  
  Open in your browser at:  
  - `http://<server-ip>/`  
  - or `https://<yourdomain.com>/` if HTTPS is enabled  

- **Minecraft Server:**  
  Connect using your Minecraft client:  
  - `mc.yourdomain.com:25565`  
  - or `<server-ip>:25565`

- **Login:**  
  Default admin account:  
  - **Username:** `admin`  
  - **Password:** `1234` (you’ll be forced to change it on first login)

- **Upload server.jar:**  
  Go to the `/install` page in the panel and upload your `server.jar`.

- **Accept EULA:**  
  Use the “Accept EULA” button in the panel.

- **Start server:**  
  Click **Start** in the web panel. Logs and player joins will appear in the live console.

---

## 🛠 Service Management

The panel runs as a **systemd service** named `mc-panel`.

```bash
# Check status
sudo systemctl status mc-panel

# Start
sudo systemctl start mc-panel

# Stop
sudo systemctl stop mc-panel

# Restart (after code changes)
sudo systemctl restart mc-panel
```

---

## 🔒 Firewall

The installer configures **ufw** to allow:

- SSH (22/tcp)
- HTTP (80/tcp)
- HTTPS (443/tcp, if enabled)
- Minecraft (25565/tcp)

---

## 📂 Paths

- **App directory:** `/opt/mc-panel`
- **Virtualenv:** `/opt/mc-panel/venv`
- **Minecraft server files:** `/opt/mc-panel/instance/server`
- **User database:** `/opt/mc-panel/instance/users.json`

---

## ✅ Tested On

- Ubuntu 22.04 LTS
- Debian 12 (Bookworm)

---

## ⚠️ Notes

- Make sure Java 21+ is installed on the server (Minecraft requires it).
- The panel only starts the Minecraft server if `server.jar` is uploaded.
- Default RAM is `-Xmx1024M -Xms1024M` (adjust in `start_server()` inside `app.py`).

---

## 🎮 Connect & Enjoy

Once installed, you can:

- Manage the Minecraft server from your browser  
- Let players connect via your **public IP or domain name**  
- Keep the server running automatically in the background
