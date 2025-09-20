from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
from flask_socketio import SocketIO
from threading import Thread
import subprocess
import threading
import os
import re
import time
import socket
import json
import datetime
import ipaddress
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file, session
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import requests  
except Exception:
    requests = None

app = Flask(
    __name__,
    instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'),
    instance_relative_config=True
)
app.config['SECRET_KEY'] = 'geheim!'
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=25, ping_interval=20, async_mode="threading")
CORS(app, resources={r"/fs-*": {"origins": "*"}})

BOOL_KEYS = {
    'allow-flight','allow-nether','broadcast-console-to-ops','broadcast-rcon-to-ops','enable-command-block',
    'enable-jmx-monitoring','enable-query','enable-rcon','enable-status','enforce-secure-profile','enforce-whitelist',
    'force-gamemode','generate-structures','hardcore','hide-online-players','log-ips','online-mode','pvp',
    'spawn-monsters','sync-chunk-writes','use-native-transport','white-list','accepts-transfers','prevent-proxy-connections','require-resource-pack'
}

SELECT_OPTIONS = {
    'difficulty': ['peaceful','easy','normal','hard'],
    'gamemode': ['survival','creative','adventure','spectator'],
    'level-type': ['minecraft:normal','minecraft:flat','minecraft:large_biomes','minecraft:amplified','minecraft:single_biome_surface'],
    'region-file-compression': ['deflate','zlib','gzip','none']
}

console_output = []
players = set()
server_process = None
SERVER_START_TS = None
USERS_FILE = os.path.join(app.instance_path, 'users.json')

JAVA_CMD = os.environ.get('JAVA_CMD', 'java')

server_files_dir = os.path.join(app.instance_path, 'server')
jar_filename = 'server.jar'
jar_path = os.path.join(server_files_dir, jar_filename)

os.makedirs(server_files_dir, exist_ok=True)


@app.before_request
def ensure_jar_present():
    ep = request.endpoint or ''
    if os.path.isfile(jar_path):
        return
    allowed_eps = {
        'install','upload_jar','static','jar_status','server_info',
        'files','fs_tree','fs_open','fs_save','fs_download',
        'login','logout','change_password'
    }

    if ep in allowed_eps:
        return
    p = request.path or ''
    if p.startswith(('/fs-tree','/fs-open','/fs-save','/fs-download','/static/')):
        return
    return redirect(url_for('install'))

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/files')
def files():
    return render_template('files.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')


@app.route('/panel-settings')
def panel_settings():
    return render_template('panel-settings.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        users = load_users()
        u = users.get(username)
        if not u or not check_password_hash(u.get('password',''), password):
            return render_template('login.html', error='Invalid credentials')
        if u.get('must_change'):
            session.clear()
            session['pending_user'] = username
            return redirect(url_for('change_password'))
        session.clear()
        session['user'] = username
        return redirect(url_for('dashboard'))
    if session.get('user'):
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/change-password', methods=['GET','POST'])
def change_password():
    pending = session.get('pending_user')
    current = session.get('user')
    who = pending or current
    if not who:
        return redirect(url_for('login'))
    if request.method == 'POST':
        p1 = request.form.get('password') or ''
        p2 = request.form.get('password2') or ''
        if len(p1) < 4 or p1 != p2:
            return render_template('change_password.html', error='Passwords must match and be at least 4 characters')
        users = load_users()
        if who not in users:
            return redirect(url_for('login'))
        users[who]['password'] = generate_password_hash(p1)
        users[who]['must_change'] = False
        save_users(users)
        session.clear()
        session['user'] = who
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/install')
def install():
    return render_template('install.html', server_dir=server_files_dir, expected=jar_filename)


@app.route('/upload-jar', methods=['POST'])
def upload_jar():
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'no file'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'ok': False, 'error': 'empty filename'}), 400
    name = f.filename.lower()
    if not name.endswith('.jar'):
        return jsonify({'ok': False, 'error': 'must be a .jar'}), 400
    os.makedirs(server_files_dir, exist_ok=True)
    tmp = os.path.join(server_files_dir, '_upload.tmp')
    f.save(tmp)
    final_path = os.path.join(server_files_dir, jar_filename)
    if os.path.exists(final_path):
        os.remove(final_path)
    os.replace(tmp, final_path)
    return jsonify({'ok': True, 'path': final_path})


@app.route('/jar-status')
def jar_status():
    exists = os.path.isfile(jar_path)
    status = "ok" if exists else "no jar file uploaded"
    return jsonify({
        'folder': server_files_dir,
        'expected_jar': jar_filename,
        'exists': exists,
        'status': status
    })


# -------------------------- Helpers --------------------------

def load_users():
    os.makedirs(app.instance_path, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except Exception:
            return {}

def save_users(users):
    os.makedirs(app.instance_path, exist_ok=True)
    tmp = USERS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(users, f)
    os.replace(tmp, USERS_FILE)

def ensure_default_admin():
    users = load_users()
    if 'admin' not in users:
        users['admin'] = {
            'password': generate_password_hash('1234'),
            'must_change': True
        }
        save_users(users)

ensure_default_admin()

@app.before_request
def require_login():
    ep = request.endpoint or ''
    p = request.path or ''
    public_eps = {
        'login','logout','change_password','static','install','upload_jar','jar_status','server_info'
    }
    if p.startswith('/static/'):
        return
    if ep in public_eps:
        return
    if not session.get('user'):
        return redirect(url_for('login'))

def server_root():
    return server_files_dir

def safe_join(rel_path: str) -> str:
    base = os.path.abspath(server_root())
    target = os.path.abspath(os.path.join(base, rel_path.lstrip("/\\")))
    if os.path.commonpath([base, target]) != base:
        raise ValueError("outside root")
    return target

def stat_entry(abs_path, rel_path):
    st = os.stat(abs_path, follow_symlinks=False)
    return {
        "name": os.path.basename(abs_path),
        "path": rel_path.replace("\\", "/"),
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
    }

def build_tree(base, rel=""):
    abs_dir = os.path.join(base, rel)
    items = []
    try:
        with os.scandir(abs_dir) as it:
            for entry in sorted(it, key=lambda e: e.name.lower()):
                if entry.name in {'.DS_Store'}:
                    continue
                rel_p = os.path.join(rel, entry.name).replace("\\", "/")
                abs_p = entry.path
                if entry.is_dir(follow_symlinks=False):
                    items.append({
                        "name": entry.name,
                        "path": rel_p,
                        "type": "dir",
                        "children": build_tree(base, rel_p)
                    })
                elif entry.is_file(follow_symlinks=False):
                    e = stat_entry(abs_p, rel_p)
                    e["type"] = "file"
                    items.append(e)
    except Exception:
        return items
    return items

@app.route("/fs-tree")
def fs_tree():
    base = server_root()
    os.makedirs(base, exist_ok=True)
    try:
        tree = build_tree(base, "")
        return jsonify({"tree": tree})
    except Exception as e:
        return jsonify({"error": str(e), "tree": []}), 500

@app.route("/fs-delete", methods=["POST"])
def fs_delete():
    data = request.get_json(force=True) or {}
    rel = data.get("path","")
    try:
        abs_p = safe_join(rel)
        if not os.path.exists(abs_p):
            return jsonify({"ok": False, "error":"not found"}), 404
        if os.path.isdir(abs_p):
            import shutil
            shutil.rmtree(abs_p)
        else:
            os.remove(abs_p)
        return jsonify({"ok": True})
    except ValueError:
        return jsonify({"ok": False, "error":"invalid path"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/fs-open", methods=["POST"])
def fs_open():
    data = request.get_json(force=True) or {}
    rel = data.get("path","")
    try:
        abs_p = safe_join(rel)
        if not os.path.isfile(abs_p):
            return jsonify({"error":"not a file"}), 400
        with open(abs_p, "rb") as f:
            blob = f.read()
        is_binary = b"\x00" in blob[:4096]
        if is_binary:
            st = os.stat(abs_p)
            return jsonify({
                "binary": True,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
            })
        text = blob.decode("utf-8", errors="replace")
        st = os.stat(abs_p)
        return jsonify({
            "binary": False,
            "content": text,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
        })
    except ValueError:
        return jsonify({"error":"invalid path"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fs-save", methods=["POST"])
def fs_save():
    data = request.get_json(force=True) or {}
    rel = data.get("path","")
    content = data.get("content","")
    try:
        abs_p = safe_join(rel)
        if not os.path.isfile(abs_p):
            return jsonify({"error":"not a file"}), 400
        with open(abs_p, "wb") as f:
            f.write(content.encode("utf-8"))
        return jsonify({"ok": True})
    except ValueError:
        return jsonify({"ok": False, "error":"invalid path"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/fs-download")
def fs_download():
    rel = request.args.get("path","")
    try:
        abs_p = safe_join(rel)
        if not os.path.isfile(abs_p):
            return "not found", 404
        return send_file(abs_p, as_attachment=True, download_name=os.path.basename(abs_p))
    except ValueError:
        return "invalid path", 400

def write_properties(path, updates):
    props = read_properties(path)
    for k,v in updates.items():
        if isinstance(v, bool):
            props[k] = 'true' if v else 'false'
        else:
            props[k] = str(v)
    lines = []
    for k,v in props.items():
        lines.append(f"{k}={v}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("#Minecraft server properties\n")
        f.write(f"#{time.strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
        for line in lines:
            f.write(line + "\n")
    os.replace(tmp, path)

@app.route('/settings-data')
def settings_data():
    props_path = os.path.join(server_files_dir, 'server.properties')
    vals = read_properties(props_path)
    return jsonify({
        'values': vals,
        'schema': {
            'options': SELECT_OPTIONS
        }
    })

@app.route('/settings-save', methods=['POST'])
def settings_save():
    props_path = os.path.join(server_files_dir, 'server.properties')
    data = request.get_json(force=True) or {}
    cleaned = {}
    for k,v in data.items():
        if k in BOOL_KEYS:
            cleaned[k] = bool(v)
        else:
            cleaned[k] = str(v).strip()
    try:
        write_properties(props_path, cleaned)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def read_properties(path):
    props = {}
    if not os.path.exists(path):
        return props
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
    return props


def get_mc_version_from_logs():
    # looks for lines like: "Starting minecraft server version 1.20.6"
    pattern = re.compile(r"Starting minecraft server version\s+([^\s]+)", re.I)
    for line in reversed(console_output[-500:]):  # last 500 lines
        m = pattern.search(line.replace('ඞ', ''))
        if m:
            return m.group(1)
    return None


def get_java_version_string():
    try:
        out = subprocess.run([JAVA_CMD, "-version"], capture_output=True, text=True)
        s = (out.stderr or out.stdout or "").strip()
        first = s.splitlines()[0] if s else ""
        return first
    except Exception:
        return None


def get_local_ip():
    try:
        # create a UDP socket to a public address (no traffic actually sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None


PUBLIC_IP_CACHE = {"ip": None, "ts": 0}


def get_public_ip(timeout=1.5):
    # cache for 60s
    now = time.time()
    if PUBLIC_IP_CACHE["ip"] and (now - PUBLIC_IP_CACHE["ts"] < 60):
        return PUBLIC_IP_CACHE["ip"]
    candidates = [
        ("https://api.ipify.org", {}),
        ("https://ifconfig.me/ip", {}),
        ("https://ipinfo.io/ip", {}),
    ]
    ip = None
    for url, params in candidates:
        try:
            if requests is None:
                break
            r = requests.get(url, timeout=timeout, params=params)
            if r.ok:
                text = r.text.strip()
                try:
                    ipaddress.ip_address(text)  # validate IPv4/IPv6
                    ip = text
                    break
                except Exception:
                    pass
        except Exception:
            continue
    PUBLIC_IP_CACHE["ip"] = ip
    PUBLIC_IP_CACHE["ts"] = now
    return ip


def is_process_alive():
    global server_process
    return bool(server_process and server_process.poll() is None)


def is_port_open(host='127.0.0.1', port=25565, timeout=0.2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def save_server_status(status):
    status_path = os.path.join(app.instance_path, 'server_status.json')
    with open(status_path, 'w') as f:
        json.dump({'server_running': status}, f)


def read_server_status():
    status_path = os.path.join(app.instance_path, 'server_status.json')
    if os.path.exists(status_path):
        with open(status_path, 'r') as f:
            return json.load(f).get('server_running', False)
    return False


def java_major():
    try:
        out = subprocess.run([JAVA_CMD, '-version'], capture_output=True, text=True)
        s = (out.stderr or out.stdout)
        m = re.search(r'version\s+"(\d+)(\.\d+)?', s)
        return int(m.group(1)) if m else None
    except Exception:
        return None


# -------------------------- Server control --------------------------

def start_server():
    global server_process, SERVER_START_TS
    if not os.path.isfile(jar_path):
        return
    ver = java_major()
    if ver is None:
        console_output.append('Error: Java not found. Install Java 21+ or set JAVA_CMD.')
        return
    if ver < 21:
        console_output.append(f'Error: Java {ver} detected. This server requires Java 21+. '
                              f'Install Java 21 and set JAVA_CMD or upgrade PATH.')
        return
    save_server_status(True)
    if server_process is None or server_process.poll() is not None:
        try:
            server_process = subprocess.Popen(
                [JAVA_CMD, "-Xmx1024M", "-Xms1024M", "-jar", jar_filename, "nogui"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=server_files_dir
            )
            SERVER_START_TS = time.time()  # mark start time on successful spawn
            threading.Thread(target=emit_server_output, args=(server_process,), daemon=True).start()
        except Exception as e:
            console_output.append(f"Server start error: {e}")


@app.route('/start')
def start_minecraft_server():
    Thread(target=start_server, daemon=True).start()
    return "Minecraft Server wird gestartet..."


def stop_server_async():
    global server_process
    if server_process is not None and server_process.stdin:
        try:
            server_process.stdin.write('/say The server will shutdown in 10 seconds\n')
            server_process.stdin.flush()
            time.sleep(7)
            for remaining in range(3, 0, -1):
                server_process.stdin.write(f'/say Stopping server in {remaining} \n')
                server_process.stdin.flush()
                time.sleep(1)
            server_process.stdin.write('stop\n')
            server_process.stdin.flush()
            server_process.wait()
        except Exception:
            pass
        finally:
            server_process = None


@app.route('/stop')
def stop_minecraft_server():
    global server_process
    save_server_status(False)
    if server_process is not None and server_process.stdin:
        Thread(target=stop_server_async, daemon=True).start()
        return jsonify({"message": "Minecraft Server shutdown initiated."})
    else:
        return jsonify({"error": "Minecraft Server is not running."}), 400


def emit_server_output(process):
    global console_output, players, server_process, SERVER_START_TS
    for line in iter(process.stdout.readline, ''):
        line_display = line.replace('<', 'ඞ').replace('>', 'ඞ')
        console_output.append(line_display)
        socketio.emit('server_output', {'data': line_display})

        join_match = re.search(r"\[Server thread/INFO\]: (\w+) joined the game", line)
        if join_match:
            players.add(join_match.group(1))
        leave_match = re.search(r"\[Server thread/INFO\]: (\w+) left the game", line)
        if leave_match:
            players.discard(leave_match.group(1))
        if "Stopping server" in line:
            players.clear()

    rc = process.poll()
    save_server_status(False)
    players.clear()
    server_process = None
    SERVER_START_TS = None
    console_output.append(f"Server process exited with code {rc}")
    socketio.emit('server_output', {'data': f"Server process exited with code {rc}"})


# -------------------------- API Routes --------------------------

@app.route('/send-command', methods=['POST'])
def send_command():
    global server_process
    command = request.json['command'] + '\n'
    try:
        if server_process and server_process.stdin and not server_process.poll():
            server_process.stdin.write(command)
            server_process.stdin.flush()
            console_output.append(f"Command: {command.strip()}")
            return jsonify({"status": "Command sent"})
        else:
            return jsonify({"error": "Server not running or input stream closed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def send_server_command(command):
    global server_process, console_output
    try:
        if server_process and server_process.stdin and not server_process.poll():
            server_process.stdin.write(f'{command}\n')
            server_process.stdin.flush()
            console_output.append(f"Command: {command.strip()}")
            return jsonify({"status": "Command sent", "command": command.strip()})
        else:
            return jsonify({"error": "Server not running or input stream closed"}), 400
    except Exception as e:
        console_output.append(f"Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/ban', methods=['POST'])
def ban_player():
    player = request.json['player']
    reason = request.json.get('reason', 'Banned by an operator.')
    return send_server_command(f'ban {player} {reason}')


@app.route('/kick', methods=['POST'])
def kick_player():
    player = request.json['player']
    reason = request.json.get('reason', 'Kicked by an operator.')
    return send_server_command(f'kick {player} {reason}')


@app.route('/kill', methods=['POST'])
def kill_player():
    player = request.json['player']
    return send_server_command(f'kill {player}')


@app.route('/op', methods=['POST'])
def op_player():
    player = request.json['player']
    return send_server_command(f'op {player}')


@app.route('/pardon', methods=['POST'])
def pardon_player():
    player = request.json['player']
    return send_server_command(f'pardon {player}')


@app.route('/deop', methods=['POST'])
def deop_player():
    player = request.json['player']
    return send_server_command(f'deop {player}')


@app.route('/get-players')
def get_players():
    return jsonify(list(players))


@app.route('/get-console-output')
def get_console_output():
    return jsonify(console_output)


@app.route('/accept-eula', methods=['POST'])
def accept_eula():
    eula_file_path = os.path.join(server_files_dir, 'eula.txt')
    try:
        if not os.path.exists(eula_file_path):
            return "EULA file not found.", 400
        with open(eula_file_path, 'r') as file:
            content = file.readlines()
        updated_content = [line.replace('eula=false', 'eula=true') for line in content]
        with open(eula_file_path, 'w') as file:
            file.writelines(updated_content)
        return "EULA accepted."
    except Exception:
        return "Ein Fehler ist aufgetreten."


@app.route('/server-status')
def server_status():
    running_flag = read_server_status()
    alive = is_process_alive()
    port_ok = is_port_open(port=25565) if alive else False
    status = 'running' if (running_flag and alive and port_ok) else ('crashed' if running_flag and not alive else 'stopped')
    return jsonify({'running': running_flag, 'alive': alive, 'port_open': port_ok, 'status': status})


@app.route('/server-info')
def server_info():
    """Return live/derived info for the UI."""
    props_path = os.path.join(server_files_dir, 'server.properties')
    props = read_properties(props_path)

    # Values from server.properties
    port = props.get('server-port', '25565')
    motd = props.get('motd', None)
    online_mode = props.get('online-mode', None)
    if isinstance(online_mode, str):
        online_mode = online_mode.strip().lower() == 'true'

    # Derived/live values
    mc_version = get_mc_version_from_logs()
    java_str = get_java_version_string()
    local_ip = get_local_ip()
    public_ip = get_public_ip()  # None if offline/firewalled

    running_flag = read_server_status()
    uptime_sec = (time.time() - SERVER_START_TS) if (SERVER_START_TS and running_flag and is_process_alive()) else 0
    uptime_human = human_duration(uptime_sec) if uptime_sec else None

    return jsonify({
        "mc_version": mc_version,
        "java_version": java_str,
        "port": port,
        "motd": motd,
        "online_mode": online_mode,
        "local_ip": local_ip,
        "public_ip": public_ip,
        "uptime_seconds": int(uptime_sec) if uptime_sec else 0,
        "uptime_human": uptime_human
    })


# -------------------------- Main --------------------------

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5003, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
