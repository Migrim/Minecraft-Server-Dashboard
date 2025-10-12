from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file, session, g, flash
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
from werkzeug.security import generate_password_hash, check_password_hash
import base64, hashlib, hmac, sqlite3
import shutil

from io import BytesIO
try:
    from PIL import Image, ImageFile, UnidentifiedImageError
    ImageFile.LOAD_TRUNCATED_IMAGES = True
except Exception:
    Image = None
    ImageFile = None
    UnidentifiedImageError = Exception

try:
    import requests
except Exception:
    requests = None

try:
    import psutil
except Exception:
    psutil = None

app = Flask(
    __name__,
    instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'),
    instance_relative_config=True
)
app.config['SECRET_KEY'] = 'geheim!'
socketio = SocketIO(app, cors_allowed_origins="*", ping_timeout=25, ping_interval=20, async_mode="threading")
CORS(app, resources={r"/fs-*": {"origins": "*"}})
HASH_METHOD = os.environ.get('HASH_METHOD', 'pbkdf2:sha256')
DB_PATH = os.path.join(app.instance_path, 'users.db')
app.config.setdefault('BOOTSTRAPPED', False)

PANEL_DEFAULTS = {
    'auto_restart': True,
    'restart_delay_sec': 10,
    'auto_start_on_boot': False,
    'min_ram_mb': 1024,
    'max_ram_mb': 2048,
    'jvm_extra': '',
    'scheduled_restart_enabled': False,
    'scheduled_restart_time': '04:30',
    'backup_on_restart': False,
    'backup_keep': 5
}

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

panel_restart_lock = threading.Lock()
last_schedule_mark = None

console_output = []
MAX_CONSOLE_LINES = 5000

def _append_console(line: str):
    global console_output
    try:
        console_output.append(line)
    except Exception:
        return
    if len(console_output) > MAX_CONSOLE_LINES:
        del console_output[0:len(console_output)-MAX_CONSOLE_LINES]
players = set()
server_process = None
SERVER_START_TS = None

JAVA_CMD = os.environ.get('JAVA_CMD', 'java')

server_files_dir = os.path.join(app.instance_path, 'server')
jar_filename = 'server.jar'
jar_path = os.path.join(server_files_dir, jar_filename)

os.makedirs(server_files_dir, exist_ok=True)

DB_PATH = os.path.join(app.instance_path, 'users.db')

def get_db():
    if 'db' not in g:
        os.makedirs(app.instance_path, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0)')
    db.commit()

def gen_hash(pw: str) -> str:
    return generate_password_hash(pw, method=HASH_METHOD)

def verify_hash(stored: str, pw: str) -> bool:
    if isinstance(stored, str) and stored.startswith('scrypt:'):
        try:
            _, rest = stored.split(':', 1)
            params, salt_b64, hash_hex = rest.split('$', 2)
            n_str, r_str, p_str = params.split(':')
            n = int(n_str); r = int(r_str); p = int(p_str)
            salt = base64.b64decode(salt_b64.encode('utf-8'))
            expected = bytes.fromhex(hash_hex)
            dklen = len(expected)
            derived = hashlib.scrypt(pw.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
            return hmac.compare_digest(derived, expected)
        except Exception:
            return False
    return check_password_hash(stored, pw)

def get_user(username: str):
    db = get_db()
    cur = db.execute('SELECT username, password, must_change FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    if not row:
        return None
    return {'username': row['username'], 'password': row['password'], 'must_change': bool(row['must_change'])}

def set_user_password(username: str, password: str, must_change: bool = False):
    db = get_db()
    ph = gen_hash(password)
    db.execute(
        'INSERT INTO users(username, password, must_change) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=excluded.password, must_change=excluded.must_change',
        (username, ph, 1 if must_change else 0)
    )
    db.commit()

def set_must_change(username: str, must_change: bool):
    db = get_db()
    db.execute('UPDATE users SET must_change=? WHERE username=?', (1 if must_change else 0, username))
    db.commit()

def ensure_default_admin():
    if not get_user('admin'):
        set_user_password('admin', '1234', must_change=True)

def reset_admin_if_env():
    if os.environ.get('RESET_ADMIN') == '1':
        set_user_password('admin', '1234', must_change=True)

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

def bootstrap_db_once():
    if app.config.get('BOOTSTRAPPED'):
        return
    os.makedirs(app.instance_path, exist_ok=True)
    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0)')
        cur = db.execute('SELECT 1 FROM users WHERE username=?', ('admin',))
        if cur.fetchone() is None:
            db.execute('INSERT INTO users(username, password, must_change) VALUES(?,?,?)',
                       ('admin', generate_password_hash('1234', method=HASH_METHOD), 1))
        if os.environ.get('RESET_ADMIN') == '1':
            db.execute('UPDATE users SET password=?, must_change=1 WHERE username=?',
                       (generate_password_hash('1234', method=HASH_METHOD), 'admin'))
        db.commit()
    ensure_panel_defaults()
    app.config['BOOTSTRAPPED'] = True

@app.before_request
def _bootstrap_guard():
    bootstrap_db_once()

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

@app.route('/panel-settings-data')
def panel_settings_data():
    return jsonify(get_panel_settings())

@app.route('/panel-settings-save', methods=['POST'])
def panel_settings_save():
    data = request.get_json(force=True) or {}
    save_panel_settings(data)
    return jsonify({'ok': True})

def stop_server_blocking(timeout=90):
    global server_process
    _write_state(phase='stopping')
    _append_console("[panel] restart: stop begin")
    if not server_process or not server_process.stdin:
        save_server_status(False)
        server_process = None
        _append_console("[panel] restart: nothing to stop")
        return True
    try:
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
        except Exception:
            pass
        t0 = time.time()
        while time.time() - t0 < timeout:
            if server_process.poll() is not None:
                break
            time.sleep(0.5)
        if server_process and server_process.poll() is None:
            _append_console("[panel] restart: terminate")
            try: server_process.terminate()
            except Exception: pass
            t1 = time.time()
            while time.time() - t1 < 10:
                if server_process.poll() is not None:
                    break
                time.sleep(0.5)
        if server_process and server_process.poll() is None:
            _append_console("[panel] restart: kill")
            try: server_process.kill()
            except Exception: pass
        save_server_status(False)
        _write_state(phase='stopped')
    finally:
        server_process = None
        _append_console("[panel] restart: stop done")
        return True

def graceful_restart_with_options(do_backup=False):
    with panel_restart_lock:
        _append_console("[panel] restart: begin")
        _write_state(phase='restarting')
        if do_backup:
            try:
                p = backup_server_folder()
                _append_console(f"[panel] restart: backup {os.path.basename(p) if p else 'none'}")
            except Exception:
                _append_console("[panel] restart: backup failed")
        stop_server_blocking(timeout=90)
        _write_state(phase='starting')
        time.sleep(1.0)
        _append_console("[panel] restart: starting")
        start_server()
        _append_console("[panel] restart: issued start")

@app.route('/restart', methods=['POST'])
def restart_server():
    do_backup = bool(get_panel_settings().get('backup_on_restart', False))
    def run():
        try:
            graceful_restart_with_options(do_backup)
        except Exception as e:
            import traceback
            _append_console(f"[panel] restart: exception {e}")
            _append_console(traceback.format_exc())
    Thread(target=run, daemon=True).start()
    return jsonify({'ok': True})

def get_panel_settings():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS panel_settings (key TEXT PRIMARY KEY, val TEXT NOT NULL)')
    cur = db.execute('SELECT key, val FROM panel_settings')
    rows = cur.fetchall()
    out = dict(PANEL_DEFAULTS)
    for r in rows:
        k = r['key']
        v = r['val']
        if k in {'auto_restart','auto_start_on_boot','scheduled_restart_enabled','backup_on_restart'}:
            out[k] = (v == '1')
        elif k in {'restart_delay_sec','min_ram_mb','max_ram_mb','backup_keep'}:
            try:
                out[k] = int(v)
            except Exception:
                pass
        else:
            out[k] = v
    return out

def save_panel_settings(updates: dict):
    if not updates:
        return
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS panel_settings (key TEXT PRIMARY KEY, val TEXT NOT NULL)')
    for k, v in updates.items():
        if k in {'auto_restart','auto_start_on_boot','scheduled_restart_enabled','backup_on_restart'}:
            val = '1' if bool(v) else '0'
        else:
            val = str(v)
        db.execute('INSERT INTO panel_settings(key,val) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET val=excluded.val', (k, val))
    db.commit()

def ensure_panel_defaults():
    cur = get_db().execute('SELECT 1 FROM sqlite_master WHERE type="table" AND name="panel_settings"')
    if not cur.fetchone():
        save_panel_settings(PANEL_DEFAULTS)
        return
    have = get_panel_settings()
    missing = {k: v for k, v in PANEL_DEFAULTS.items() if k not in have}
    if missing:
        save_panel_settings(missing)

def backup_server_folder():
    os.makedirs(app.instance_path, exist_ok=True)
    src = server_files_dir
    if not os.path.isdir(src):
        return None
    out_dir = os.path.join(app.instance_path, 'server-backups')
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
    base = os.path.join(out_dir, f'Backup {ts}')
    archive = shutil.make_archive(base, 'zip', src)
    keep = max(1, int(get_panel_settings().get('backup_keep', 5)))
    files = sorted([os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.endswith('.zip')])
    if len(files) > keep:
        for f in files[:len(files)-keep]:
            try:
                os.remove(f)
            except Exception:
                pass
    return archive

def graceful_restart_with_options(do_backup=False):
    if do_backup:
        try:
            backup_server_folder()
        except Exception:
            pass
    stop_server_async()
    t0 = time.time()
    while is_process_alive() and time.time() - t0 < 60:
        time.sleep(0.5)
    start_server()

def watchdog_loop():
    with app.app_context():
        while True:
            try:
                s = get_panel_settings()
                if s.get('auto_restart', True):
                    running_flag = read_server_status()
                    alive = is_process_alive()
                    if running_flag and not alive:
                        d = int(s.get('restart_delay_sec', 10))
                        time.sleep(max(0, d))
                        if read_server_status() and not is_process_alive():
                            _write_state(phase='starting')
                            start_server()
                time.sleep(2)
            except Exception:
                time.sleep(2)

def schedule_loop():
    with app.app_context():
        global last_schedule_mark
        while True:
            try:
                s = get_panel_settings()
                if s.get('scheduled_restart_enabled', False):
                    hhmm = str(s.get('scheduled_restart_time','04:30'))
                    now = datetime.now()
                    if now.strftime('%H:%M') == hhmm:
                        mark = now.strftime('%Y-%m-%d %H:%M')
                        if last_schedule_mark != mark:
                            last_schedule_mark = mark
                            with panel_restart_lock:
                                graceful_restart_with_options(bool(s.get('backup_on_restart', False)))
                time.sleep(20)
            except Exception:
                time.sleep(5)

def backups_dir():
    return os.path.join(app.instance_path, 'server-backups')

def list_backups():
    out = []
    bdir = backups_dir()
    if not os.path.isdir(bdir):
        return out
    for name in sorted(os.listdir(bdir)):
        if not name.endswith('.zip'):
            continue
        p = os.path.join(bdir, name)
        try:
            st = os.stat(p)
            out.append({
                'name': name,
                'size_bytes': st.st_size,
                'mtime': datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')
            })
        except Exception:
            continue
    return list(reversed(out))

@app.route('/backups-list')
def backups_list():
    return jsonify({'items': list_backups()})

@app.route('/backup-create', methods=['POST'])
def backup_create():
    path = backup_server_folder()
    if not path:
        return jsonify({'ok': False}), 500
    return jsonify({'ok': True, 'name': os.path.basename(path)})

@app.route('/backup-download')
def backup_download():
    name = request.args.get('name','')
    if not name or '/' in name or '\\' in name or not name.endswith('.zip'):
        return 'invalid', 400
    bdir = backups_dir()
    fp = os.path.join(bdir, name)
    if not os.path.isfile(fp):
        return 'not found', 404
    return send_file(fp, as_attachment=True, download_name=name)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        u = get_user(username)
        if not u:
            return render_template('login.html', error='Invalid credentials')
        ok = verify_hash(u.get('password',''), password)
        if not ok and username == 'admin' and os.environ.get('ALLOW_ADMIN_1234_FALLBACK') == '1' and password == '1234':
            set_user_password('admin', '1234', must_change=False)
            ok = True
        if not ok:
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
        if not get_user(who):
            return redirect(url_for('login'))
        set_user_password(who, p1, must_change=False)
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

@app.route("/fs-upload", methods=["POST"])
def fs_upload():
    try:
        rel = request.form.get("path", "") or ""
        folder = safe_join(rel)
        os.makedirs(folder, exist_ok=True)
        files = request.files.getlist("file")
        if not files:
            return jsonify({"ok": False, "error": "no files"}), 400
        saved = 0
        for f in files:
            name = secure_filename(f.filename or "")
            if not name:
                continue
            dest = os.path.join(folder, name)
            base, ext = os.path.splitext(dest)
            i = 1
            while os.path.exists(dest):
                dest = f"{base} ({i}){ext}"
                i += 1
            f.save(dest)
            saved += 1
        return jsonify({"ok": True, "saved": saved})
    except ValueError:
        return jsonify({"ok": False, "error": "invalid path"}), 400
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

@app.route("/fs-rename", methods=["POST"])
def fs_rename():
    data = request.get_json(force=True) or {}
    rel = (data.get("path") or "").strip()
    new_name = (data.get("new_name") or "").strip()
    if not rel or not new_name or "/" in new_name or "\\" in new_name or new_name in {".", ".."}:
        return jsonify({"ok": False, "error": "invalid name"}), 400
    try:
        abs_old = safe_join(rel)
        if not os.path.exists(abs_old):
            return jsonify({"ok": False, "error": "not found"}), 404
        rel_dir = os.path.dirname(rel)
        new_rel = os.path.join(rel_dir, new_name).replace("\\", "/")
        abs_new = safe_join(new_rel)
        if os.path.exists(abs_new):
            return jsonify({"ok": False, "error": "target exists"}), 409
        os.replace(abs_old, abs_new)
        return jsonify({"ok": True, "path": new_rel})
    except ValueError:
        return jsonify({"ok": False, "error": "invalid path"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/fs-mkdir", methods=["POST"])
def fs_mkdir():
    data = request.get_json(force=True) or {}
    rel = (data.get("path") or "").strip()
    if not rel:
        return jsonify({"ok": False, "error": "missing path"}), 400
    try:
        abs_p = safe_join(rel)
        if os.path.exists(abs_p):
            return jsonify({"ok": False, "error": "already exists"}), 409
        os.makedirs(abs_p, exist_ok=False)
        return jsonify({"ok": True})
    except ValueError:
        return jsonify({"ok": False, "error": "invalid path"}), 400
    except FileExistsError:
        return jsonify({"ok": False, "error": "already exists"}), 409
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
    pattern = re.compile(r"Starting minecraft server version\s+([^\s]+)", re.I)
    for line in reversed(console_output[-500:]):
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
                    ipaddress.ip_address(text)
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

def start_server():
    with app.app_context():
        global server_process, SERVER_START_TS
        if is_process_alive():
            _append_console("[panel] start: already running")
            _write_state(phase='running', server_running=True)
            return
        if not os.path.isfile(jar_path):
            _append_console("[panel] start: jar missing")
            return
        ver = java_major()
        if ver is None:
            _append_console("Error: Java not found. Install Java 21+ or set JAVA_CMD.")
            _write_state(phase='starting', server_running=True)
            return
        if ver < 21:
            _append_console(f"Error: Java {ver} detected. This server requires Java 21+.")
            return
        save_server_status(True)
        try:
            s = get_panel_settings()
            xms = max(256, int(s.get('min_ram_mb', 1024)))
            xmx = max(xms, int(s.get('max_ram_mb', 2048)))
            jextra = str(s.get('jvm_extra','')).strip()
            args = [JAVA_CMD, f'-Xmx{xmx}M', f'-Xms{xms}M']
            if jextra: args += jextra.split()
            args += ['-jar', jar_filename, 'nogui']
            server_process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, cwd=server_files_dir
            )
            SERVER_START_TS = time.time()
            threading.Thread(target=emit_server_output, args=(server_process,), daemon=True).start()
            _append_console("[panel] start: process spawned")
        except Exception as e:
            _append_console(f"Server start error: {e}")

@app.route('/start')
def start_minecraft_server():
    Thread(target=start_server, daemon=True).start()
    return "Starting the Minecraft Server..."

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
    _write_state(phase='stopped')
    if server_process is not None and server_process.stdin:
        Thread(target=stop_server_async, daemon=True).start()
        return jsonify({"message": "Minecraft Server shutdown initiated."})
    else:
        return jsonify({"error": "Minecraft Server is not running."}), 400

def emit_server_output(process):
    global console_output, players, server_process, SERVER_START_TS
    for line in iter(process.stdout.readline, ''):
        line_display = line.replace('<', 'ඞ').replace('>', 'ඞ')
        _append_console(line_display)
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
    _append_console(f"Server process exited with code {rc}")
    socketio.emit('server_output', {'data': f"Server process exited with code {rc}"})

@app.route('/send-command', methods=['POST'])
def send_command():
    global server_process
    command = request.json['command'] + '\n'
    try:
        if server_process and server_process.stdin and not server_process.poll():
            server_process.stdin.write(command)
            server_process.stdin.flush()
            _append_console(f"Command: {command.strip()}")
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
            _append_console(f"Command: {command.strip()}")
            return jsonify({"status": "Command sent", "command": command.strip()})
        else:
            return jsonify({"error": "Server not running or input stream closed"}), 400
    except Exception as e:
        _append_console(f"Error: {e}")
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

STATE_PATH = os.path.join(app.instance_path, 'server_status.json')

def _read_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, 'r') as f:
            return json.load(f)
    return {'server_running': False, 'phase': 'stopped'}

def _write_state(**updates):
    os.makedirs(app.instance_path, exist_ok=True)
    cur = _read_state()
    cur.update({k: v for k, v in updates.items() if v is not None})
    with open(STATE_PATH, 'w') as f:
        json.dump(cur, f)

def save_server_status(status):
    _write_state(server_running=status)

def read_server_status():
    return _read_state().get('server_running', False)


# ---- BEGIN system metrics endpoints ----

CPU_SNAPSHOT = {"total": None, "idle": None, "ts": 0}

def _read_proc_stat_totals():
    try:
        with open('/proc/stat','r') as f:
            line = f.readline()
        if not line.startswith('cpu '):
            return None, None
        parts = [int(x) for x in line.split()[1:11]]
        idle = parts[3] + parts[4]
        total = sum(parts)
        return total, idle
    except Exception:
        return None, None

def _cpu_percent_proc(interval=0.25):
    t1, i1 = _read_proc_stat_totals()
    if t1 is None:
        return None
    time.sleep(interval)
    t2, i2 = _read_proc_stat_totals()
    if t2 is None:
        return None
    dt = t2 - t1
    di = i2 - i1
    if dt <= 0:
        return None
    used = dt - di
    return max(0.0, min(100.0, (used / dt) * 100.0))

def _cpu_percent():
    val = None
    if psutil:
        try:
            psutil.cpu_percent(None)
            val = psutil.cpu_percent(interval=0.25)
        except Exception:
            val = None
    if val is None or val == 0.0:
        alt = _cpu_percent_proc(0.25)
        if alt is not None:
            val = alt
    return val

def _read_uptime_seconds():
    try:
        with open('/proc/uptime','r') as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return 0

def _meminfo_fallback():
    out = {}
    try:
        with open('/proc/meminfo','r') as f:
            for line in f:
                if ":" in line:
                    k,v = line.split(":",1)
                    try:
                        out[k.strip()] = int(v.strip().split()[0]) * 1024
                    except Exception:
                        pass
    except Exception:
        pass
    total = out.get('MemTotal')
    available = out.get('MemAvailable') or out.get('MemFree')
    used = total - available if total and available else None
    percent = int((used/total)*100) if used and total else None
    swap_total = out.get('SwapTotal')
    swap_free = out.get('SwapFree')
    swap_used = swap_total - swap_free if swap_total and swap_free else None
    swap_percent = int((swap_used/swap_total)*100) if swap_used and swap_total else None
    return {
        'total': total,
        'available': available,
        'used': used,
        'free': out.get('MemFree'),
        'percent': percent,
        'swap': {
            'total': swap_total,
            'used': swap_used,
            'free': swap_free,
            'percent': swap_percent
        }
    }

def _disk_usage_fallback(path):
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - free
        percent = int((used/total)*100) if total else None
        return {'path': path, 'total': total, 'used': used, 'free': free, 'percent': percent}
    except Exception:
        return {'path': path, 'total': None, 'used': None, 'free': None, 'percent': None}

def get_system_metrics():
    cpu_percent = _cpu_percent()
    loadavg = None
    mem = None
    swap = None
    disks = {}
    net = None
    procs = None
    try:
        loadavg = os.getloadavg()
    except Exception:
        loadavg = None
    if psutil:
        try:
            vm = psutil.virtual_memory()
            sm = psutil.swap_memory()
            mem = {
                'total': vm.total,
                'available': vm.available,
                'used': vm.used,
                'free': vm.free,
                'percent': int(vm.percent)
            }
            swap = {
                'total': sm.total,
                'used': sm.used,
                'free': sm.free,
                'percent': int(sm.percent)
            }
        except Exception:
            mem = None
        for p in {'/': '/', 'instance': app.instance_path, 'server': server_files_dir}:
            path = p if isinstance(p, str) else p
            try:
                du = psutil.disk_usage(path)
                disks[path] = {'path': path, 'total': du.total, 'used': du.used, 'free': du.free, 'percent': int(du.percent)}
            except Exception:
                disks[path] = _disk_usage_fallback(path)
        try:
            io = psutil.net_io_counters()
            net = {'bytes_sent': io.bytes_sent, 'bytes_recv': io.bytes_recv, 'packets_sent': io.packets_sent, 'packets_recv': io.packets_recv}
        except Exception:
            net = None
        try:
            procs = len(psutil.pids())
        except Exception:
            procs = None
    else:
        meminfo = _meminfo_fallback()
        mem = {k: meminfo.get(k) for k in ['total','available','used','free','percent']}
        swap = meminfo.get('swap')
        for path in ['/', app.instance_path, server_files_dir]:
            disks[path] = _disk_usage_fallback(path)
    return {
        'cpu_percent': cpu_percent,
        'loadavg': {'1m': loadavg[0], '5m': loadavg[1], '15m': loadavg[2]} if loadavg else None,
        'memory': mem,
        'swap': swap,
        'disks': disks,
        'network': net,
        'processes': procs,
        'uptime_seconds': _read_uptime_seconds(),
        'cores': os.cpu_count(),
        'timestamp': int(time.time())
    }

@app.route('/system/metrics')
def system_metrics():
    return jsonify(get_system_metrics())

@app.route('/system/cpu')
def system_cpu():
    m = get_system_metrics()
    return jsonify({'cpu_percent': m.get('cpu_percent'), 'loadavg': m.get('loadavg')})

@app.route('/system/memory')
def system_memory():
    m = get_system_metrics()
    return jsonify({'memory': m.get('memory'), 'swap': m.get('swap')})

@app.route('/system/storage')
def system_storage():
    m = get_system_metrics()
    disks = m.get('disks') or {}
    server_paths = {server_files_dir, '/server', '/server/'}
    filtered = {k: v for k, v in disks.items() if k not in {'server', 'Server'} and ((v or {}).get('path') not in server_paths)}
    return jsonify({'disks': filtered})

@app.route('/healthz')
def healthz():
    alive = is_process_alive()
    st = _read_state()
    return jsonify({'ok': True, 'server_alive': alive, 'status': st.get('phase'), 'uptime_system_seconds': _read_uptime_seconds()})
# ---- END system metrics endpoints ----

def _process_server_icon(data_bytes: bytes, keep_aspect: bool = False) -> str:
    if Image is None:
        raise RuntimeError('Pillow not installed')
    if not data_bytes or len(data_bytes) < 16:
        raise ValueError('empty or invalid data')
    if len(data_bytes) > 20 * 1024 * 1024:
        raise ValueError('file too large')
    bio = BytesIO(data_bytes)
    try:
        img = Image.open(bio)
        img.load()
    except UnidentifiedImageError:
        raise ValueError('unsupported image format')
    except Exception as e:
        raise ValueError(str(e))
    img = img.convert('RGBA')
    if keep_aspect:
        canvas = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        tmp = img.copy()
        tmp.thumbnail((64, 64), Image.LANCZOS)
        w2, h2 = tmp.size
        ox = (64 - w2) // 2
        oy = (64 - h2) // 2
        canvas.paste(tmp, (ox, oy))
        img = canvas
    else:
        w, h = img.size
        if w != h:
            side = min(w, h)
            left = (w - side) // 2
            top = (h - side) // 2
            img = img.crop((left, top, left + side, top + side))
        img = img.resize((64, 64), Image.LANCZOS)
    os.makedirs(server_files_dir, exist_ok=True)
    out_path = os.path.join(server_files_dir, 'server-icon.png')
    img.save(out_path, format='PNG')
    return out_path

@app.route('/server-icon', methods=['GET','POST'])
def server_icon_route():
    if request.method == 'GET':
        p = os.path.join(server_files_dir, 'server-icon.png')
        raw = request.args.get('raw')
        if raw == '1' and os.path.isfile(p):
            return send_file(p, mimetype='image/png')
        exists = os.path.isfile(p)
        size = None
        if exists:
            try:
                st = os.stat(p)
                size = st.st_size
            except Exception:
                size = None
        return jsonify({'exists': exists, 'size': size})
    keep_aspect = False
    val = request.form.get('keep_aspect') or (request.json.get('keep_aspect') if request.is_json else None)
    if isinstance(val, str) and val.lower() in {'1','true','yes','on'}:
        keep_aspect = True
    if 'file' in request.files:
        f = request.files['file']
        blob = f.read()
    else:
        url = request.form.get('url') or (request.json.get('url') if request.is_json else None)
        if url and requests is not None:
            r = requests.get(url, timeout=10)
            if not r.ok:
                return jsonify({'ok': False, 'error': 'download failed'}), 400
            ctype = (r.headers.get('Content-Type') or '').lower()
            if 'image' not in ctype and not url.lower().endswith(('.png','.jpg','.jpeg','.webp','.bmp','.gif','.tiff','.tif','.heic','.heif')):
                return jsonify({'ok': False, 'error': 'url is not an image'}), 400
            blob = r.content
        else:
            return jsonify({'ok': False, 'error': 'no file or url'}), 400
    try:
        _process_server_icon(blob, keep_aspect=keep_aspect)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/server-status')
def server_status():
    st = _read_state()
    running_flag = st.get('server_running', False)
    phase = st.get('phase')
    alive = is_process_alive()
    port_ok = is_port_open(port=25565) if alive else False
    if phase in {'restarting','stopping','starting'}:
        status = phase
    else:
        status = 'running' if (running_flag and alive and port_ok) else ('crashed' if running_flag and not alive else 'stopped')
    return jsonify({'running': running_flag, 'alive': alive, 'port_open': port_ok, 'status': status, 'phase': status})

@app.route('/server-info')
def server_info():
    props_path = os.path.join(server_files_dir, 'server.properties')
    props = read_properties(props_path)
    port = props.get('server-port', '25565')
    motd = props.get('motd', None)
    online_mode = props.get('online-mode', None)
    if isinstance(online_mode, str):
        online_mode = online_mode.strip().lower() == 'true'
    mc_version = get_mc_version_from_logs()
    java_str = get_java_version_string()
    local_ip = get_local_ip()
    public_ip = get_public_ip()
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

if __name__ == '__main__':
    with app.app_context():
        init_db()
        ensure_default_admin()
        reset_admin_if_env()
        ensure_panel_defaults()
        s = get_panel_settings()
        threading.Thread(target=watchdog_loop, daemon=True).start()
        threading.Thread(target=schedule_loop, daemon=True).start()
        if s.get('auto_start_on_boot', False) and os.path.isfile(jar_path) and not is_process_alive():
            start_server()
    socketio.run(app, host="127.0.0.1", port=5003, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)