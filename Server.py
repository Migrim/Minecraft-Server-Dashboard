from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file, session, g, flash, abort
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
import uuid
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import base64, hashlib, hmac, sqlite3
import shutil
import zipfile, tempfile
import struct

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
playtime_store = {}
player_join_times = {}  # username -> join timestamp (float)

CHUNK_UPLOADS = {}
CHUNK_UPLOADS_LOCK = threading.Lock()

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
    'backup_keep': 5,
    'accent_color': '#c2553d',
    'accent_text_mode': 'auto',
    'discord_server_name': '',
    'discord_webhook_enabled': False,
    'discord_webhook_url': '',
    'discord_notify_start': True,
    'discord_notify_stop': True,
    'discord_notify_restart': True,
    'discord_notify_crash': True,
    'discord_player_webhook_enabled': False,
    'discord_player_webhook_url': '',
    'discord_notify_join': True,
    'discord_notify_leave': True,
    'discord_notify_playtime': True,
    'discord_notify_achievement': True,
    'discord_notify_death': True,
    'discord_notify_first_join': True,
    'discord_chat_webhook_enabled': False,
    'discord_chat_webhook_url': '',
    'bluemap_port': 8100,
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
restore_jobs = {}
restore_jobs_lock = threading.Lock()
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
run_script_path = os.path.join(server_files_dir, 'run.sh')

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

def _feature_folder_exists(kind: str) -> bool:
    return os.path.isdir(os.path.join(server_files_dir, kind))

def _has_bluemap() -> bool:
    if os.path.isdir(os.path.join(server_files_dir, 'bluemap')):
        return True
    for folder in ('plugins', 'mods'):
        d = os.path.join(server_files_dir, folder)
        if os.path.isdir(d):
            for name in os.listdir(d):
                if name.lower().startswith('bluemap') and name.lower().endswith('.jar'):
                    return True
    return False

@app.context_processor
def inject_feature_flags():
    panel = get_panel_settings()
    accent_color = _clean_hex_color(panel.get('accent_color', '#c2553d'))
    accent_text_mode = _clean_accent_text_mode(panel.get('accent_text_mode', 'auto'))
    return {
        'has_plugins': _feature_folder_exists('plugins'),
        'has_mods': _feature_folder_exists('mods'),
        'has_bluemap': _has_bluemap(),
        'panel_settings': panel,
        'panel_accent_color': accent_color,
        'panel_accent_fg': _accent_foreground(accent_color, accent_text_mode),
    }

@app.before_request
def ensure_jar_present():
    ep = request.endpoint or ''
    if os.path.isfile(jar_path) or os.path.isfile(run_script_path):
        return
    if not session.get('user'):
        return  # not logged in — require_login handles the redirect to /login
    allowed_eps = {
        'install', 'upload_jar', 'upload_forge_folder', 'upload_chunk', 'static', 'jar_status',
        'files', 'fs_tree', 'fs_open', 'fs_save', 'fs_download',
        'login', 'logout', 'change_password'
    }
    if ep in allowed_eps:
        return
    p = request.path or ''
    if p.startswith(('/fs-tree', '/fs-open', '/fs-save', '/fs-download', '/static/')):
        return
    return redirect(url_for('install'))

@app.before_request
def require_login():
    ep = request.endpoint or ''
    p = request.path or ''
    public_eps = {
        'login', 'logout', 'change_password', 'static', 'install', 'jar_status'
    }
    if p.startswith('/static/'):
        return
    if ep in public_eps:
        return
    if not session.get('user'):
        return redirect(url_for('login'))
    u = get_user(session['user'])
    if u and u.get('must_change'):
        session.clear()
        session['pending_user'] = u['username']
        return redirect(url_for('change_password'))

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
    # Clean up any stale chunk upload directories from a previous run
    _chunk_base = os.path.join(app.instance_path, 'chunks')
    if os.path.isdir(_chunk_base):
        try: shutil.rmtree(_chunk_base)
        except Exception: pass
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


# ---- Added simple mods/plugins page routes ----#

def _require_feature_folder(kind: str):
    if not _feature_folder_exists(kind):
        abort(404)

@app.route('/mods')
def mods_page():
    _require_feature_folder('mods')
    return render_template('mods.html')

@app.route('/plugins')
def plugins_page():
    _require_feature_folder('plugins')
    return render_template('plugins.html')

@app.route('/map')
def map_page():
    if not _has_bluemap():
        abort(404)
    bluemap_port = int(get_panel_settings().get('bluemap_port', 8100))
    return render_template('map.html', bluemap_port=bluemap_port)

@app.route('/panel-settings-data')
def panel_settings_data():
    return jsonify(get_panel_settings())

@app.route('/panel-settings-save', methods=['POST'])
def panel_settings_save():
    data = request.get_json(force=True) or {}
    save_panel_settings(data)
    return jsonify({'ok': True})

def stop_server_blocking(timeout=90, announce=None, countdown_label='Stopping server in', countdown_from=3, lead_delay=7):
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
            msg = announce or 'The server will shutdown in 10 seconds'
            server_process.stdin.write(f'/say {msg}\n')
            server_process.stdin.flush()
            time.sleep(max(0, lead_delay))
            for remaining in range(int(countdown_from), 0, -1):
                server_process.stdin.write(f'/say {countdown_label} {remaining}\n')
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
        if k in {'auto_restart','auto_start_on_boot','scheduled_restart_enabled','backup_on_restart',
                  'discord_webhook_enabled','discord_notify_start','discord_notify_stop',
                  'discord_notify_restart','discord_notify_crash','discord_player_webhook_enabled',
                  'discord_notify_join','discord_notify_leave','discord_notify_playtime',
                  'discord_notify_achievement','discord_notify_death','discord_notify_first_join','discord_chat_webhook_enabled'}:
            out[k] = (v == '1')
        elif k in {'restart_delay_sec','min_ram_mb','max_ram_mb','backup_keep'}:
            try:
                out[k] = int(v)
            except Exception:
                pass
        elif k == 'accent_color':
            out[k] = _clean_hex_color(v)
        elif k == 'accent_text_mode':
            out[k] = _clean_accent_text_mode(v)
        else:
            out[k] = v
    return out

def _clean_hex_color(value, fallback='#c2553d'):
    if not isinstance(value, str):
        return fallback
    value = value.strip()
    if re.fullmatch(r'#[0-9a-fA-F]{6}', value):
        return value.lower()
    return fallback

def _clean_accent_text_mode(value):
    return value if value in {'auto', 'white', 'dark'} else 'auto'

def _accent_foreground(hex_color, mode='auto'):
    mode = _clean_accent_text_mode(mode)
    if mode == 'white':
        return '#fff8f3'
    if mode == 'dark':
        return '#2a221a'
    color = _clean_hex_color(hex_color).lstrip('#')
    r = int(color[0:2], 16)
    g = int(color[2:4], 16)
    b = int(color[4:6], 16)
    luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
    return '#2a221a' if luminance > 0.62 else '#fff8f3'

def save_panel_settings(updates: dict):
    if not updates:
        return
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS panel_settings (key TEXT PRIMARY KEY, val TEXT NOT NULL)')
    for k, v in updates.items():
        if k in {'auto_restart','auto_start_on_boot','scheduled_restart_enabled','backup_on_restart',
                  'discord_webhook_enabled','discord_notify_start','discord_notify_stop',
                  'discord_notify_restart','discord_notify_crash','discord_player_webhook_enabled',
                  'discord_notify_join','discord_notify_leave','discord_notify_playtime',
                  'discord_notify_achievement','discord_notify_death','discord_notify_first_join','discord_chat_webhook_enabled'}:
            val = '1' if bool(v) else '0'
        elif k == 'accent_color':
            val = _clean_hex_color(v)
        elif k == 'accent_text_mode':
            val = _clean_accent_text_mode(v)
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

    now = datetime.now()
    weekday = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'][now.weekday()]
    ts_display = now.strftime('%d-%m-%Y at %H:%M:%S')
    safe_name = f"Backup - {weekday} {ts_display}"
    base = os.path.join(out_dir, safe_name)

    try:
        archive = shutil.make_archive(base, 'zip', root_dir=src)
    except Exception:
        # Fallback: create zip explicitly to avoid platform quirks
        archive = base + '.zip'
        try:
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(src):
                    for fname in files:
                        ap = os.path.join(root, fname)
                        rp = os.path.relpath(ap, src)
                        zf.write(ap, rp)
        except Exception:
            return None

    keep = max(1, int(get_panel_settings().get('backup_keep', 5)))
    try:
        all_archives = [os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.lower().endswith('.zip')]
        all_archives.sort(key=lambda p: os.stat(p).st_mtime)  # oldest first
        if len(all_archives) > keep:
            for p in all_archives[:-keep]:
                try:
                    os.remove(p)
                except Exception:
                    pass
    except Exception:
        pass

    return archive

def stop_server_for_restart(timeout=60):
    global server_process
    if server_process is None or not server_process.stdin:
        save_server_status(False)
        server_process = None
        return
    try:
        for remaining in range(5, 0, -1):
            server_process.stdin.write(f'/say rebooting in {remaining}\n')
            server_process.stdin.flush()
            time.sleep(1)
        server_process.stdin.write('stop\n')
        server_process.stdin.flush()
        server_process.wait(timeout=timeout)
    except Exception:
        try:
            if server_process and server_process.poll() is None:
                server_process.terminate()
                server_process.wait(timeout=10)
        except Exception:
            try:
                if server_process and server_process.poll() is None:
                    server_process.kill()
            except Exception:
                pass
    finally:
        save_server_status(False)
        _write_state(phase='stopped')
        server_process = None

def graceful_restart_with_options(do_backup=False):
    _append_console("[panel] restart: begin")
    _write_state(phase='restarting')
    _fire_webhook_async('restarting')
    if do_backup:
        try:
            backup_server_folder()
        except Exception:
            pass
    stop_server_for_restart()
    t0 = time.time()
    while is_process_alive() and time.time() - t0 < 60:
        time.sleep(0.5)
    _write_state(phase='starting')
    _append_console("[panel] restart: starting")
    start_server()

def watchdog_loop():
    with app.app_context():
        while True:
            try:
                s = get_panel_settings()
                if s.get('auto_restart', True) and not is_locked():
                    running_flag = read_server_status()
                    alive = is_process_alive()
                    if running_flag and not alive:
                        d = int(s.get('restart_delay_sec', 10))
                        time.sleep(max(0, d))
                        if read_server_status() and not is_process_alive():
                            _fire_webhook_async('crashed')
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
    items = []
    for name in os.listdir(bdir):
        if not name.lower().endswith('.zip'):
            continue
        p = os.path.join(bdir, name)
        try:
            st = os.stat(p)
            items.append((p, name, st.st_mtime, st.st_size))
        except Exception:
            continue
    items.sort(key=lambda t: t[2], reverse=True)
    for p, name, mtime, size in items:
        out.append({
            'name': name,
            'size_bytes': size,
            'mtime': datetime.fromtimestamp(mtime).isoformat(timespec='seconds')
        })
    return out

@app.route('/backups-list')
def backups_list():
    return jsonify({'items': list_backups()})

@app.route('/backup-create', methods=['POST'])
def backup_create():
    path = backup_server_folder()
    if not path:
        return jsonify({'ok': False}), 500
    return jsonify({'ok': True, 'name': os.path.basename(path)})

@app.route('/backup-delete', methods=['POST'])
def backup_delete():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    if not name or '/' in name or '\\' in name or not name.endswith('.zip'):
        return jsonify({'ok': False, 'error': 'invalid name'}), 400
    bdir = backups_dir()
    fp = os.path.join(bdir, name)
    if not os.path.isfile(fp):
        return jsonify({'ok': False, 'error': 'not found'}), 404
    try:
        os.remove(fp)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

def _clear_directory(path):
    for entry in os.listdir(path):
        p = os.path.join(path, entry)
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except Exception:
            pass

def _copy_tree(src, dst):
    for entry in os.listdir(src):
        s = os.path.join(src, entry)
        d = os.path.join(dst, entry)
        if os.path.isdir(s):
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)

def restore_backup_archive(archive_path):
    if not os.path.isfile(archive_path):
        raise FileNotFoundError('archive not found')
    tmp = tempfile.mkdtemp(prefix='restore-')
    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extractall(tmp)
        src_root = tmp
        items = os.listdir(tmp)
        if len(items) == 1 and os.path.isdir(os.path.join(tmp, items[0])):
            src_root = os.path.join(tmp, items[0])
        os.makedirs(server_files_dir, exist_ok=True)
        _clear_directory(server_files_dir)
        _copy_tree(src_root, server_files_dir)
    finally:
        try:
            shutil.rmtree(tmp)
        except Exception:
            pass

def wait_for_server_started(timeout=180):
    props_path = os.path.join(server_files_dir, 'server.properties')
    props = read_properties(props_path)
    try:
        port = int(props.get('server-port', '25565'))
    except Exception:
        port = 25565
    t0 = time.time()
    while time.time() - t0 < timeout:
        if is_process_alive() and is_port_open(port=port):
            _write_state(phase='running', server_running=True)
            return True
        if server_process is not None and server_process.poll() is not None:
            break
        time.sleep(0.5)
    return False

@app.route('/backup-restore', methods=['POST'])
def backup_restore():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    if not name or '/' in name or '\\' in name or not name.endswith('.zip'):
        return jsonify({'ok': False, 'error': 'invalid name'}), 400
    bdir = backups_dir()
    fp = os.path.join(bdir, name)
    if not os.path.isfile(fp):
        return jsonify({'ok': False, 'error': 'not found'}), 404
    job_id = uuid.uuid4().hex
    def set_restore_status(step, error=None):
        payload = {'step': step, 'updated_at': time.time()}
        if error:
            payload['error'] = str(error)
        with restore_jobs_lock:
            restore_jobs[job_id] = payload
            if len(restore_jobs) > 25:
                stale = sorted(restore_jobs.items(), key=lambda item: item[1].get('updated_at', 0))[:-25]
                for old_id, _ in stale:
                    restore_jobs.pop(old_id, None)
        socketio.emit('restore_progress', payload)

    with restore_jobs_lock:
        restore_jobs[job_id] = {'step': 'queued', 'updated_at': time.time()}

    def do_restore(path):
        locked = False
        try:
            set_restore_status('locking')
            locked = panel_restart_lock.acquire(timeout=5)
            if not locked:
                raise RuntimeError('Another panel operation is running. Try again after it finishes.')
            set_lock(True)
            _write_state(phase='restoring', server_running=False)
            set_restore_status('stopping')
            _append_console("[panel] restore: warning players before stop")
            stop_server_blocking(
                timeout=90,
                announce='Backup restore starting. Server will stop in 10 seconds',
                countdown_label='Loading backup in',
                countdown_from=5,
                lead_delay=5,
            )
            save_server_status(False)
            set_restore_status('replacing')
            restore_backup_archive(path)
            _write_state(phase='stopped', server_running=False)
            set_restore_status('unlocking')
            set_lock(False)
            set_restore_status('starting')
            _append_console("[panel] restore: starting server")
            start_server()
            if not wait_for_server_started(timeout=180):
                raise RuntimeError('Backup restored, but server did not finish starting.')
            set_restore_status('done')
        except Exception as e:
            try:
                set_lock(False)
            except Exception:
                pass
            set_restore_status('error', e)
        finally:
            if locked:
                panel_restart_lock.release()
    t = threading.Thread(target=do_restore, args=(fp,), daemon=True)
    t.start()
    return jsonify({'ok': True, 'job_id': job_id})

@app.route('/backup-restore-status')
def backup_restore_status():
    job_id = (request.args.get('id') or '').strip()
    with restore_jobs_lock:
        status = restore_jobs.get(job_id)
    if not status:
        return jsonify({'ok': False, 'error': 'restore job not found'}), 404
    return jsonify({'ok': True, **status})

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

@app.route('/upload-forge-folder', methods=['POST'])
def upload_forge_folder():
    os.makedirs(server_files_dir, exist_ok=True)
    base = os.path.abspath(server_files_dir)

    def safe_dest(rel_path):
        parts = [p for p in rel_path.replace('\\', '/').split('/') if p and p not in ('.', '..')]
        if not parts:
            return None
        dest = os.path.join(server_files_dir, *parts)
        if not os.path.abspath(dest).startswith(base):
            return None
        return dest

    # ZIP upload
    if 'zip' in request.files:
        f = request.files['zip']
        if not (f.filename or '').lower().endswith('.zip'):
            return jsonify({'ok': False, 'error': 'Please upload a .zip file'}), 400
        tmp = os.path.join(app.instance_path, '_forge_upload.zip')
        try:
            f.save(tmp)
            with zipfile.ZipFile(tmp, 'r') as zf:
                members = [m for m in zf.namelist() if m and not m.startswith('__MACOSX')]
                tops = set(m.split('/')[0] for m in members)
                strip = ''
                if len(tops) == 1:
                    candidate = list(tops)[0] + '/'
                    if all(m == candidate.rstrip('/') or m.startswith(candidate) for m in members):
                        strip = candidate
                for member in members:
                    rel = member[len(strip):] if strip and member.startswith(strip) else member
                    if not rel or rel.endswith('/'):
                        continue
                    dest = safe_dest(rel)
                    if not dest:
                        continue
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with zf.open(member) as src, open(dest, 'wb') as dst:
                        dst.write(src.read())
        except zipfile.BadZipFile:
            return jsonify({'ok': False, 'error': 'Invalid ZIP file'}), 400
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass
        return jsonify({'ok': True})

    # Folder files upload (webkitdirectory)
    files = request.files.getlist('files')
    if not files:
        return jsonify({'ok': False, 'error': 'No files received'}), 400
    saved = 0
    for f in files:
        raw = (f.filename or '').replace('\\', '/')
        parts = [p for p in raw.split('/') if p and p not in ('.', '..')]
        if len(parts) > 1:
            parts = parts[1:]  # strip top-level folder name
        if not parts:
            continue
        dest = safe_dest('/'.join(parts))
        if not dest:
            continue
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            f.save(dest)
            saved += 1
        except Exception:
            pass
    if not saved:
        return jsonify({'ok': False, 'error': 'No files could be saved'}), 400
    return jsonify({'ok': True, 'saved': saved})

@app.route('/upload-chunk', methods=['POST'])
def upload_chunk():
    upload_id  = (request.form.get('upload_id')  or '').strip()
    dest_type  = (request.form.get('dest_type')  or 'jar').strip()
    filename   = secure_filename(request.form.get('filename') or '')

    if dest_type not in ('jar', 'forge-zip'):
        return jsonify({'ok': False, 'error': 'invalid dest_type'}), 400
    if not upload_id or not re.match(r'^[a-zA-Z0-9_\-]{4,64}$', upload_id):
        return jsonify({'ok': False, 'error': 'invalid upload_id'}), 400
    if not filename:
        return jsonify({'ok': False, 'error': 'missing filename'}), 400
    if dest_type == 'jar' and not filename.lower().endswith('.jar'):
        return jsonify({'ok': False, 'error': 'must be a .jar'}), 400
    if dest_type == 'forge-zip' and not filename.lower().endswith('.zip'):
        return jsonify({'ok': False, 'error': 'must be a .zip'}), 400

    try:
        chunk_index  = int(request.form.get('chunk_index',  '0'))
        total_chunks = int(request.form.get('total_chunks', '1'))
    except ValueError:
        return jsonify({'ok': False, 'error': 'invalid chunk params'}), 400
    if chunk_index < 0 or total_chunks < 1 or chunk_index >= total_chunks:
        return jsonify({'ok': False, 'error': 'chunk index out of range'}), 400

    chunk_data = request.files.get('chunk')
    if chunk_data is None:
        return jsonify({'ok': False, 'error': 'missing chunk data'}), 400

    chunk_dir = os.path.join(app.instance_path, 'chunks', upload_id)
    os.makedirs(chunk_dir, exist_ok=True)
    chunk_data.save(os.path.join(chunk_dir, f'{chunk_index:08d}.part'))

    with CHUNK_UPLOADS_LOCK:
        entry = CHUNK_UPLOADS.setdefault(upload_id, {
            'total': total_chunks, 'filename': filename,
            'dest_type': dest_type, 'received': set(),
            'assembling': False, 'ts': time.time()
        })
        entry['received'].add(chunk_index)
        received_count = len(entry['received'])
        should_assemble = (received_count >= total_chunks and not entry['assembling'])
        if should_assemble:
            entry['assembling'] = True

    if not should_assemble:
        return jsonify({'ok': True, 'done': False,
                        'received': received_count, 'total': total_chunks})

    tmp_path = os.path.join(app.instance_path, f'_chunk_{upload_id}.tmp')
    try:
        os.makedirs(server_files_dir, exist_ok=True)
        with open(tmp_path, 'wb') as out_f:
            for idx in range(total_chunks):
                with open(os.path.join(chunk_dir, f'{idx:08d}.part'), 'rb') as in_f:
                    shutil.copyfileobj(in_f, out_f)

        if dest_type == 'jar':
            final = os.path.join(server_files_dir, jar_filename)
            if os.path.exists(final):
                os.remove(final)
            os.replace(tmp_path, final)
            return jsonify({'ok': True, 'done': True})

        # forge-zip: extract into server folder
        base_abs = os.path.abspath(server_files_dir)
        def _safe_zip(rel):
            parts = [p for p in rel.replace('\\', '/').split('/') if p and p not in ('.', '..')]
            if not parts:
                return None
            d = os.path.join(server_files_dir, *parts)
            return d if os.path.abspath(d).startswith(base_abs) else None

        with zipfile.ZipFile(tmp_path, 'r') as zf:
            members = [m for m in zf.namelist() if m and not m.startswith('__MACOSX')]
            tops = {m.split('/')[0] for m in members}
            strip = ''
            if len(tops) == 1:
                cand = list(tops)[0] + '/'
                if all(m == cand.rstrip('/') or m.startswith(cand) for m in members):
                    strip = cand
            for member in members:
                rel = member[len(strip):] if strip and member.startswith(strip) else member
                if not rel or rel.endswith('/'):
                    continue
                dst = _safe_zip(rel)
                if not dst:
                    continue
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with zf.open(member) as src, open(dst, 'wb') as dst_f:
                    shutil.copyfileobj(src, dst_f)
        return jsonify({'ok': True, 'done': True})

    except zipfile.BadZipFile:
        return jsonify({'ok': False, 'error': 'Invalid ZIP file'}), 400
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    finally:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception: pass
        try: shutil.rmtree(chunk_dir)
        except Exception: pass
        with CHUNK_UPLOADS_LOCK:
            CHUNK_UPLOADS.pop(upload_id, None)

@app.route('/feature-flags')
def feature_flags():
    return jsonify({
        'has_mods': _feature_folder_exists('mods'),
        'has_plugins': _feature_folder_exists('plugins'),
        'has_bluemap': _has_bluemap(),
    })

@app.route('/jar-status')
def jar_status():
    has_jar = os.path.isfile(jar_path)
    has_run = os.path.isfile(run_script_path)
    exists = has_jar or has_run
    mode = 'run.sh' if has_run else ('jar' if has_jar else None)
    status = 'ok' if exists else 'no launcher present'
    return jsonify({
        'folder': server_files_dir,
        'expected_jar': jar_filename,
        'exists': exists,
        'mode': mode,
        'run_script': has_run,
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

@app.route("/fs-raw")
def fs_raw():
    rel = request.args.get("path","")
    try:
        abs_p = safe_join(rel)
        if not os.path.isfile(abs_p):
            return "not found", 404
        return send_file(
            abs_p,
            as_attachment=False,
            download_name=os.path.basename(abs_p),
            conditional=False
        )
    except ValueError:
        return "invalid path", 400

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

@app.route("/fs-download", methods=["GET","POST"]) 
def fs_download():
    rel = request.args.get("path","")
    if not rel and request.is_json:
        data = request.get_json(silent=True) or {}
        rel = (data.get("path") or "").strip()
    if not rel and request.form:
        rel = (request.form.get("path") or "").strip()
    try:
        abs_p = safe_join(rel)
        if not os.path.isfile(abs_p):
            return "not found", 404
        return send_file(
            abs_p,
            as_attachment=True,
            download_name=os.path.basename(abs_p),
            conditional=False
        )
    except ValueError:
        return "invalid path", 400
    except Exception as e:
        return str(e), 500

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

def get_forge_info_from_logs():
    """Return (forge_version, mc_version) if Forge is confirmed running, else (None, None).

    Forge is only considered active when the permission handler init line appears,
    which is logged after Forge has fully loaded all mods.
    """
    lines = [l.replace('ඞ', '') for l in console_output[-500:]]
    confirmed = any('forge:default_handler' in l for l in lines)
    if not confirmed:
        return None, None
    ver_pattern = re.compile(r"Forge mod loading,\s+version\s+([\d.]+),\s+for MC\s+([\d.]+)", re.I)
    for line in lines:
        m = ver_pattern.search(line)
        if m:
            return m.group(1), m.group(2)
    return 'unknown', None

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
        if is_locked():
            _append_console("[panel] start: locked")
            _write_state(phase='locked', server_running=False)
            return
        global server_process, SERVER_START_TS
        if is_process_alive():
            _append_console("[panel] start: already running")
            _write_state(phase='running', server_running=True)
            return
        use_run = os.path.isfile(run_script_path)
        if not use_run and not os.path.isfile(jar_path):
            _append_console("[panel] start: jar missing")
            return
        if use_run:
            _write_state(phase='starting', server_running=True)
            save_server_status(True)
            try:
                args = ['bash', 'run.sh']
                server_process = subprocess.Popen(
                    args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, cwd=server_files_dir
                )
                SERVER_START_TS = time.time()
                threading.Thread(target=emit_server_output, args=(server_process,), daemon=True).start()
                _append_console("[panel] start: using run.sh")
                def _monitor_startup():
                    try:
                        props_path = os.path.join(server_files_dir, 'server.properties')
                        props = read_properties(props_path)
                        try:
                            port = int(props.get('server-port', '25565'))
                        except Exception:
                            port = 25565
                        t0 = time.time()
                        while time.time() - t0 < 120:
                            if _read_state().get('phase') == 'running':
                                return
                            if not is_process_alive():
                                phase = 'stopped' if not read_server_status() else 'crashed'
                                _write_state(phase=phase, server_running=False)
                                return
                            if is_port_open(port=port):
                                _write_state(phase='running', server_running=True)
                                return
                            time.sleep(0.5)
                        if is_process_alive():
                            _write_state(phase='running', server_running=True)
                        else:
                            _write_state(phase='crashed', server_running=False)
                    except Exception:
                        pass
                threading.Thread(target=_monitor_startup, daemon=True).start()
            except Exception as e:
                _append_console(f"Server start error: {e}")
            return
        ver = java_major()
        if ver is None:
            _append_console("Error: Java not found. Install Java 21+ or set JAVA_CMD.")
            _write_state(phase='starting', server_running=True)
            return
        if ver < 21:
            _append_console(f"Error: Java {ver} detected. This server requires Java 21+.")
            return
        _write_state(phase='starting', server_running=True)
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
            def _monitor_startup():
                try:
                    props_path = os.path.join(server_files_dir, 'server.properties')
                    props = read_properties(props_path)
                    try:
                        port = int(props.get('server-port', '25565'))
                    except Exception:
                        port = 25565
                    t0 = time.time()
                    while time.time() - t0 < 120:
                        if _read_state().get('phase') == 'running':
                            return
                        if not is_process_alive():
                            phase = 'stopped' if not read_server_status() else 'crashed'
                            _write_state(phase=phase, server_running=False)
                            return
                        if is_port_open(port=port):
                            _write_state(phase='running', server_running=True)
                            return
                        time.sleep(0.5)
                    if is_process_alive():
                        _write_state(phase='running', server_running=True)
                    else:
                        _write_state(phase='crashed', server_running=False)
                except Exception:
                    pass
            threading.Thread(target=_monitor_startup, daemon=True).start()
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
            save_server_status(False)
            _write_state(phase='stopped')
            server_process = None

def force_stop_server():
    global server_process
    proc = server_process
    save_server_status(False)
    _write_state(phase='stopping')
    _append_console("[panel] stop: forced")
    if proc is not None and proc.poll() is None:
        try:
            if proc.stdin:
                proc.stdin.write('stop\n')
                proc.stdin.flush()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        finally:
            server_process = None
    _write_state(phase='stopped')

@app.route('/stop')
def stop_minecraft_server():
    global server_process
    save_server_status(False)
    _write_state(phase='stopping')
    if server_process is not None and server_process.stdin:
        _fire_webhook_async('stopped')
        Thread(target=stop_server_async, daemon=True).start()
        return jsonify({"message": "Minecraft Server shutdown initiated."})
    else:
        _write_state(phase='stopped')
        return jsonify({"error": "Minecraft Server is not running."}), 400

@app.route('/force-stop', methods=['POST'])
def force_stop_minecraft_server():
    _fire_webhook_async('stopped')
    force_stop_server()
    return jsonify({"message": "Minecraft Server stopped immediately."})

@app.route('/cancel-start', methods=['POST'])
def cancel_minecraft_start():
    global server_process
    st = _read_state()
    if st.get('phase') != 'starting':
        return jsonify({"error": "Minecraft Server is not starting."}), 400
    proc = server_process
    save_server_status(False)
    _write_state(phase='stopping')
    _append_console("[panel] start: cancelled")
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        finally:
            server_process = None
    _write_state(phase='stopped')
    return jsonify({"message": "Minecraft Server startup cancelled."})

def emit_server_output(process):
    global console_output, players, server_process, SERVER_START_TS, player_join_times
    for line in iter(process.stdout.readline, ''):
        line_display = line.replace('<', 'ඞ').replace('>', 'ඞ')
        _append_console(line_display)
        socketio.emit('server_output', {'data': line_display})

        join_match = re.search(r"\[Server thread/INFO\]: (\w+) joined the game", line)
        if join_match:
            name = join_match.group(1)
            players.add(name)
            player_join_times[name] = time.time()
            _fire_player_webhook_async('join', name)
            _check_first_join_async(name)

        leave_match = re.search(r"\[Server thread/INFO\]: (\w+) left the game", line)
        if leave_match:
            name = leave_match.group(1)
            players.discard(name)
            joined_at = player_join_times.pop(name, None)
            playtime_str = ''
            if joined_at is not None:
                secs = int(time.time() - joined_at)
                h, rem = divmod(secs, 3600)
                m, s = divmod(rem, 60)
                playtime_str = (f'{h}h {m}m {s}s' if h else f'{m}m {s}s') if secs >= 60 else f'{secs}s'
            _fire_player_webhook_async('leave', name, playtime_str)

        adv_match = re.search(r"\[Server thread/INFO\]: (\w+) has (?:made the advancement|completed the challenge|reached the goal) \[(.+?)\]", line)
        if adv_match:
            _fire_player_webhook_async('achievement', adv_match.group(1), adv_match.group(2))

        death_match = re.search(
            r"\[Server thread/INFO\]: (\w+) "
            r"(?:was |fell |drowned|burned|suffocated|starved|hit the ground|died|blew up|withered|walked into|tried to swim|froze|experienced kinetic|was squished|was pummeled|was shot|was skewered|was fireballed|was killed|was impaled|was struck)",
            line)
        if death_match:
            name = death_match.group(1)
            raw_msg = re.sub(r'^\[\d+:\d+:\d+\] \[Server thread/INFO\]: ', '', line).strip()
            _fire_player_webhook_async('death', name, raw_msg)

        chat_match = re.search(r"\[Server thread/INFO\]: <(\w+)> (.+)", line)
        if chat_match:
            _fire_chat_webhook_async(chat_match.group(1), chat_match.group(2).strip())

        if "Stopping server" in line:
            players.clear()
            player_join_times.clear()
        if re.search(r'\[Server thread/INFO\].*:\s*Done\b', line):
            _write_state(phase='running', server_running=True)
            _fire_webhook_async('started')
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
    raw = request.json['command']
    command = (raw.lstrip('/') if raw.startswith('/') else raw) + '\n'
    try:
        if server_process and server_process.stdin and not server_process.poll():
            server_process.stdin.write(command)
            server_process.stdin.flush()
            _append_console(f"[{time.strftime('%H:%M:%S')}] [Panel Command]: {command.strip()}")
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
            _append_console(f"[{time.strftime('%H:%M:%S')}] [Panel Command]: {command.strip()}")
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

@app.route('/clear-console-output', methods=['POST'])
def clear_console_output():
    console_output.clear()
    return jsonify({'ok': True})

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

LOCK_PATH = os.path.join(app.instance_path, 'restore.lock')

def set_lock(enabled: bool):
    os.makedirs(app.instance_path, exist_ok=True)
    if enabled:
        with open(LOCK_PATH, 'w') as f:
            f.write('1')
    else:
        try:
            os.remove(LOCK_PATH)
        except Exception:
            pass

def is_locked() -> bool:
    return os.path.exists(LOCK_PATH)

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



# ---- BEGIN mods/plugins management endpoints ----

def _ensure_feature_folder(kind: str) -> str:
    if kind not in {"plugins", "mods"}:
        raise ValueError("invalid kind")
    p = os.path.join(server_files_dir, kind)
    os.makedirs(p, exist_ok=True)
    return p

def _is_valid_package_name(name: str) -> bool:
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        return False
    lower = name.lower()
    return lower.endswith(".jar") or lower.endswith(".jar.disabled")

def _detect_mod_type(jar_path: str):
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            names = z.namelist()
            if 'META-INF/neoforge.mods.toml' in names:
                return 'NeoForge'
            if 'META-INF/mods.toml' in names:
                return 'Forge'
            if 'fabric.mod.json' in names:
                return 'Fabric'
            if 'quilt.mod.json' in names:
                return 'Quilt'
    except Exception:
        pass
    return None

def _detect_plugin_type(jar_path: str):
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            names = z.namelist()
            if 'paper-plugin.yml' in names:
                return 'Paper'
            if 'bungee.yml' in names:
                return 'BungeeCord'
            if 'plugin.yml' in names:
                content = z.read('plugin.yml').decode('utf-8', errors='replace')
                if re.search(r'^api-version\s*:', content, re.MULTILINE):
                    return 'Spigot'
                return 'Bukkit'
    except Exception:
        pass
    return None

def _list_packages(kind: str):
    folder = _ensure_feature_folder(kind)
    items = []
    try:
        for n in sorted(os.listdir(folder), key=lambda x: x.lower()):
            if not _is_valid_package_name(n):
                continue
            fp = os.path.join(folder, n)
            if not os.path.isfile(fp):
                continue
            st = os.stat(fp)
            enabled = not n.lower().endswith('.disabled')
            base = n[:-9] if n.lower().endswith('.disabled') else n
            item = {
                'name': base,
                'filename': n,
                'enabled': enabled,
                'size_bytes': st.st_size,
                'mtime': datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds')
            }
            if kind == 'plugins':
                item['plugin_type'] = _detect_plugin_type(fp)
            elif kind == 'mods':
                item['mod_type'] = _detect_mod_type(fp)
            items.append(item)
    except Exception:
        pass
    return items

def _resolve_package_path(kind: str, name: str):
    folder = _ensure_feature_folder(kind)
    name = os.path.basename(name or "")
    cand_enabled = os.path.join(folder, name if name.lower().endswith('.jar') else name + ('' if name.lower().endswith('.jar') else ''))
    if not cand_enabled.lower().endswith('.jar') and not cand_enabled.lower().endswith('.jar.disabled'):
        cand_enabled = os.path.join(folder, name + '.jar')
    cand_disabled = cand_enabled + '.disabled' if not cand_enabled.lower().endswith('.disabled') else cand_enabled
    if os.path.isfile(cand_enabled):
        return cand_enabled
    if os.path.isfile(cand_disabled):
        return cand_disabled
    return None

def _toggle_package(kind: str, name: str, enable: bool):
    p = _resolve_package_path(kind, name)
    if not p:
        return False, 'not found'
    is_disabled = p.lower().endswith('.disabled')
    if enable and is_disabled:
        dst = p[:-9]
        if os.path.exists(dst):
            return False, 'target exists'
        os.replace(p, dst)
        return True, None
    if not enable and not is_disabled:
        dst = p + '.disabled'
        if os.path.exists(dst):
            return False, 'target exists'
        os.replace(p, dst)
        return True, None
    return True, None

def _delete_package(kind: str, name: str):
    p = _resolve_package_path(kind, name)
    if not p:
        return False, 'not found'
    try:
        os.remove(p)
        return True, None
    except Exception as e:
        return False, str(e)

def _rename_package(kind: str, old_name: str, new_name: str):
    src = _resolve_package_path(kind, old_name)
    if not src:
        return False, 'not found'
    if not new_name or '/' in new_name or '\\' in new_name or new_name in {'.','..'}:
        return False, 'invalid name'
    keep_disabled = src.lower().endswith('.disabled')
    base = new_name if new_name.lower().endswith('.jar') else (new_name + '.jar')
    if keep_disabled:
        base += '.disabled'
    dst = os.path.join(_ensure_feature_folder(kind), os.path.basename(base))
    if os.path.exists(dst):
        return False, 'target exists'
    try:
        os.replace(src, dst)
        return True, None
    except Exception as e:
        return False, str(e)

@app.route('/plugins/list')
def plugins_list():
    return jsonify({'items': _list_packages('plugins')})

@app.route('/plugins/upload', methods=['POST'])
def plugins_upload():
    folder = _ensure_feature_folder('plugins')
    files = request.files.getlist('file')
    if not files:
        return jsonify({'ok': False, 'error': 'no files'}), 400
    saved = 0
    out = []
    for f in files:
        name = secure_filename(f.filename or '')
        if not name or not name.lower().endswith('.jar'):
            continue
        dest = os.path.join(folder, name)
        base, ext = os.path.splitext(dest)
        i = 1
        while os.path.exists(dest):
            dest = f"{base} ({i}){ext}"
            i += 1
        f.save(dest)
        saved += 1
        out.append(os.path.basename(dest))
    if not saved:
        return jsonify({'ok': False, 'error': 'no valid files'}), 400
    return jsonify({'ok': True, 'saved': saved, 'files': out})

@app.route('/plugins/toggle', methods=['POST'])
def plugins_toggle():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    enable = bool(data.get('enable', True))
    ok, err = _toggle_package('plugins', name, enable)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

@app.route('/plugins/delete', methods=['POST'])
def plugins_delete():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    ok, err = _delete_package('plugins', name)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

@app.route('/plugins/rename', methods=['POST'])
def plugins_rename():
    data = request.get_json(force=True) or {}
    old = (data.get('old_name') or '').strip()
    new = (data.get('new_name') or '').strip()
    ok, err = _rename_package('plugins', old, new)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

@app.route('/mods/list')
def mods_list():
    return jsonify({'items': _list_packages('mods')})

@app.route('/mods/upload', methods=['POST'])
def mods_upload():
    folder = _ensure_feature_folder('mods')
    files = request.files.getlist('file')
    if not files:
        return jsonify({'ok': False, 'error': 'no files'}), 400
    saved = 0
    out = []
    for f in files:
        name = secure_filename(f.filename or '')
        if not name or not name.lower().endswith('.jar'):
            continue
        dest = os.path.join(folder, name)
        base, ext = os.path.splitext(dest)
        i = 1
        while os.path.exists(dest):
            dest = f"{base} ({i}){ext}"
            i += 1
        f.save(dest)
        saved += 1
        out.append(os.path.basename(dest))
    if not saved:
        return jsonify({'ok': False, 'error': 'no valid files'}), 400
    return jsonify({'ok': True, 'saved': saved, 'files': out})

@app.route('/mods/toggle', methods=['POST'])
def mods_toggle():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    enable = bool(data.get('enable', True))
    ok, err = _toggle_package('mods', name, enable)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

@app.route('/mods/delete', methods=['POST'])
def mods_delete():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    ok, err = _delete_package('mods', name)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

@app.route('/mods/rename', methods=['POST'])
def mods_rename():
    data = request.get_json(force=True) or {}
    old = (data.get('old_name') or '').strip()
    new = (data.get('new_name') or '').strip()
    ok, err = _rename_package('mods', old, new)
    if not ok:
        return jsonify({'ok': False, 'error': err}), 400
    return jsonify({'ok': True})

# ---- END mods/plugins management endpoints ----

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

def _process_server_icon(data_bytes: bytes, keep_aspect: bool = False, zoom: float = 1.0, offset_x: float = 0.0, offset_y: float = 0.0) -> str:
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
        try:
            zoom = max(1.0, min(4.0, float(zoom or 1.0)))
        except Exception:
            zoom = 1.0
        try:
            offset_x = max(-128.0, min(128.0, float(offset_x or 0.0)))
            offset_y = max(-128.0, min(128.0, float(offset_y or 0.0)))
        except Exception:
            offset_x = 0.0
            offset_y = 0.0
        base_scale = max(256.0 / max(w, 1), 256.0 / max(h, 1))
        scale = base_scale * zoom
        crop_w = 256.0 / scale
        crop_h = 256.0 / scale
        left = (w / 2.0) - (crop_w / 2.0) - (offset_x / scale)
        top = (h / 2.0) - (crop_h / 2.0) - (offset_y / scale)
        img = img.crop((left, top, left + crop_w, top + crop_h))
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
    zoom = request.form.get('zoom') or (request.json.get('zoom') if request.is_json else 1)
    offset_x = request.form.get('offset_x') or (request.json.get('offset_x') if request.is_json else 0)
    offset_y = request.form.get('offset_y') or (request.json.get('offset_y') if request.is_json else 0)
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
        _process_server_icon(blob, keep_aspect=keep_aspect, zoom=zoom, offset_x=offset_x, offset_y=offset_y)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/server-icon-delete', methods=['POST'])
def server_icon_delete():
    p = os.path.join(server_files_dir, 'server-icon.png')
    try:
        if os.path.isfile(p):
            os.remove(p)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

def _mc_slp_query(host='127.0.0.1', port=25565, timeout=2.0):
    """Query Minecraft server via Server List Ping. Returns {online, max} or None."""
    def write_varint(v):
        out = bytearray()
        while True:
            seg = v & 0x7F
            v >>= 7
            if v:
                seg |= 0x80
            out.append(seg)
            if not v:
                return bytes(out)

    def read_varint(conn):
        n = 0
        for shift in range(0, 35, 7):
            raw = conn.recv(1)
            if not raw:
                raise ConnectionError('disconnected')
            b = raw[0]
            n |= (b & 0x7F) << shift
            if not (b & 0x80):
                return n
        raise OverflowError('varint too long')

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        host_bytes = host.encode('utf-8')
        payload = (write_varint(0x00) +
                   write_varint(764) +
                   write_varint(len(host_bytes)) + host_bytes +
                   struct.pack('>H', int(port)) +
                   write_varint(1))
        sock.sendall(write_varint(len(payload)) + payload)
        sr = write_varint(0x00)
        sock.sendall(write_varint(len(sr)) + sr)
        read_varint(sock)
        read_varint(sock)
        json_len = read_varint(sock)
        buf = b''
        while len(buf) < json_len:
            chunk = sock.recv(min(4096, json_len - len(buf)))
            if not chunk:
                break
            buf += chunk
        data = json.loads(buf.decode('utf-8'))
        p = data.get('players', {})
        return {'online': p.get('online', 0), 'max': p.get('max', 0)}
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

@app.route('/server-players')
def server_players():
    props_path = os.path.join(server_files_dir, 'server.properties')
    props = read_properties(props_path)
    try:
        port = int(props.get('server-port', 25565))
    except Exception:
        port = 25565
    result = _mc_slp_query(host='127.0.0.1', port=port)
    if result is None:
        return jsonify({'online': None, 'max': None, 'available': False})
    return jsonify({'online': result['online'], 'max': result['max'], 'available': True})

def _discord_embed(title, description, color, fields=None, footer=None, author_name=None, author_icon=None):
    embed = {
        'description': description,
        'color': color,
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'footer': {'text': footer or 'Minecraft Server Dashboard'},
    }
    if title:
        embed['title'] = title
    if fields:
        embed['fields'] = fields
    if author_name:
        author = {'name': author_name}
        if author_icon:
            author['icon_url'] = author_icon
        embed['author'] = author
    return embed

def _render_favicon_png(accent='#c2553d', size=64):
    try:
        from PIL import Image, ImageDraw
        scale = size / 32
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=max(1, round(7 * scale)), fill=accent)
        w = max(1, round(2 * scale))
        def pt(x, y):
            return (round(x * scale), round(y * scale))
        draw.line([pt(16,6), pt(6,11), pt(6,21), pt(16,26), pt(26,21), pt(26,11), pt(16,6)], fill='#fff8f3', width=w)
        draw.line([pt(6,11), pt(16,16), pt(26,11)], fill='#fff8f3', width=w)
        draw.line([pt(16,16), pt(16,26)], fill='#fff8f3', width=w)
        buf = BytesIO()
        img.save(buf, 'PNG')
        return buf.getvalue()
    except Exception:
        return None

def _fire_webhook_async(event, detail=''):
    def _send():
        try:
            with app.app_context():
                s = get_panel_settings()
                if not s.get('discord_webhook_enabled'):
                    return
                toggle_map = {
                    'started':    'discord_notify_start',
                    'stopped':    'discord_notify_stop',
                    'restarting': 'discord_notify_restart',
                    'crashed':    'discord_notify_crash',
                }
                toggle_key = toggle_map.get(event)
                if toggle_key and not s.get(toggle_key, True):
                    return
                url = str(s.get('discord_webhook_url', '')).strip()
                if not url or not requests:
                    return
                mc_ver = get_mc_version_from_logs() or '?'
                sname = str(s.get('discord_server_name', '')).strip() or f'Minecraft {mc_ver}'
                accent = str(s.get('accent_color', '#c2553d'))
                footer = f'Minecraft {mc_ver}'

                icon_bytes = _render_favicon_png(accent)
                icon_url = 'attachment://favicon.png' if icon_bytes else None

                if event == 'started':
                    desc = f'**{sname}** is now online!'
                    color = 0x57f287
                elif event == 'stopped':
                    desc = f'**{sname}** has shut down.'
                    color = 0x949ba4
                elif event == 'crashed':
                    desc = f'**{sname}** crashed unexpectedly.'
                    if s.get('auto_restart'):
                        desc += ' Restarting shortly.'
                    if detail:
                        desc += f'\n```\n{detail[:300]}\n```'
                    color = 0xed4245
                elif event == 'restarting':
                    desc = f'**{sname}** is restarting…'
                    color = 0xf0a500
                else:
                    desc = detail or event.title()
                    color = 0x5865f2

                embed = _discord_embed(None, desc, color, None, footer, author_name=sname, author_icon=icon_url)

                if icon_bytes:
                    payload = {'embeds': [embed], 'attachments': [{'id': 0, 'filename': 'favicon.png'}]}
                    requests.post(url, data={'payload_json': json.dumps(payload)},
                                  files={'files[0]': ('favicon.png', icon_bytes, 'image/png')}, timeout=5)
                else:
                    requests.post(url, json={'embeds': [embed]}, timeout=5)
        except Exception:
            pass
    Thread(target=_send, daemon=True).start()

def _fire_player_webhook_async(event, player, detail=''):
    def _send():
        try:
            with app.app_context():
                s = get_panel_settings()
                if not s.get('discord_player_webhook_enabled'):
                    return
                toggle_map = {
                    'join':        'discord_notify_join',
                    'leave':       'discord_notify_leave',
                    'achievement': 'discord_notify_achievement',
                    'death':       'discord_notify_death',
                    'first_join':  'discord_notify_first_join',
                }
                toggle_key = toggle_map.get(event)
                if toggle_key and not s.get(toggle_key, True):
                    return
                url = str(s.get('discord_player_webhook_url', '')).strip()
                if not url or not requests:
                    return
                mc_ver = get_mc_version_from_logs() or '?'
                sname = str(s.get('discord_server_name', '')).strip() or None
                head_url = f'https://mc-heads.net/avatar/{player}/64'
                footer = sname or f'Minecraft {mc_ver}'

                if event == 'join':
                    embed = _discord_embed(
                        None,
                        f'**{player}** has joined the server!',
                        0x57f287, None, footer, author_name=player, author_icon=head_url)
                elif event == 'leave':
                    fields = []
                    if detail and s.get('discord_notify_playtime', True):
                        fields.append({'name': 'Session', 'value': detail, 'inline': True})
                    embed = _discord_embed(
                        None,
                        f'**{player}** has left the server.',
                        0x949ba4, fields or None, footer, author_name=player, author_icon=head_url)
                elif event == 'achievement':
                    fields = [{'name': 'Advancement', 'value': detail or '—', 'inline': False}]
                    embed = _discord_embed(
                        'New Advancement',
                        f'**{player}** just earned an advancement!',
                        0xfee75c, fields, footer, author_name=player, author_icon=head_url)
                elif event == 'death':
                    body = detail if detail else f'**{player}** met their end.'
                    embed = _discord_embed(None, body, 0xed4245, None, footer, author_name=player, author_icon=head_url)
                elif event == 'first_join':
                    embed = _discord_embed(
                        'First time on the server!',
                        f'Welcome **{player}** — joining for the very first time!',
                        0xf59e0b, None, footer, author_name=player, author_icon=head_url)
                else:
                    embed = _discord_embed(player, detail or '', 0x5865f2, None, footer, author_name=player, author_icon=head_url)

                requests.post(url, json={'embeds': [embed]}, timeout=5)
        except Exception:
            pass
    Thread(target=_send, daemon=True).start()

def _fire_chat_webhook_async(player, message):
    def _send():
        try:
            with app.app_context():
                s = get_panel_settings()
                if not s.get('discord_chat_webhook_enabled'):
                    return
                url = str(s.get('discord_chat_webhook_url', '')).strip()
                if not url or not requests:
                    return
                sname = str(s.get('discord_server_name', '')).strip() or None
                head_url = f'https://mc-heads.net/avatar/{player}/64'
                footer = sname or 'MC Panel'
                embed = _discord_embed(None, message, 0x5865f2, None, footer, author_name=player, author_icon=head_url)
                requests.post(url, json={'embeds': [embed]}, timeout=5)
        except Exception:
            pass
    Thread(target=_send, daemon=True).start()

def _check_first_join_async(player):
    def _check():
        try:
            with app.app_context():
                db = get_db()
                db.execute('CREATE TABLE IF NOT EXISTS seen_players (name TEXT PRIMARY KEY)')
                cur = db.execute('INSERT OR IGNORE INTO seen_players (name) VALUES (?)', (player,))
                db.commit()
                if cur.rowcount:
                    _fire_player_webhook_async('first_join', player)
        except Exception:
            pass
    Thread(target=_check, daemon=True).start()

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
    try:
        max_players = int(props.get('max-players', 20))
    except (ValueError, TypeError):
        max_players = 20
    if isinstance(online_mode, str):
        online_mode = online_mode.strip().lower() == 'true'
    mc_version = get_mc_version_from_logs()
    java_str = get_java_version_string()
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    running_flag = read_server_status()
    uptime_sec = (time.time() - SERVER_START_TS) if (SERVER_START_TS and running_flag and is_process_alive()) else 0
    uptime_human = human_duration(uptime_sec) if uptime_sec else None
    forge_ver, _ = get_forge_info_from_logs()
    loader = 'Forge' if forge_ver else None
    def _count_packages(kind):
        if not _feature_folder_exists(kind):
            return None, None
        items = _list_packages(kind)
        return len(items), sum(1 for i in items if i['enabled'])
    mods_total, mods_enabled = _count_packages('mods')
    plugins_total, plugins_enabled = _count_packages('plugins')
    return jsonify({
        "mc_version": mc_version,
        "java_version": java_str,
        "port": port,
        "motd": motd,
        "online_mode": online_mode,
        "local_ip": local_ip,
        "public_ip": public_ip,
        "uptime_seconds": int(uptime_sec) if uptime_sec else 0,
        "uptime_human": uptime_human,
        "loader": loader,
        "forge_version": forge_ver,
        "mods_total": mods_total,
        "mods_enabled": mods_enabled,
        "plugins_total": plugins_total,
        "plugins_enabled": plugins_enabled,
        "max_players": max_players,
    })

@app.route('/reinstall', methods=['POST'])
def reinstall():
    global console_output
    force_stop_server()
    try:
        if os.path.isdir(server_files_dir):
            shutil.rmtree(server_files_dir)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    console_output.clear()
    return jsonify({'ok': True})

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
