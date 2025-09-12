from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO
from threading import Thread
import subprocess
import threading
import os
import re
import time
import json

app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'), instance_relative_config=True)
app.config['SECRET_KEY'] = 'geheim!'
socketio = SocketIO(app)

console_output = []
players = set()
server_process = None

JAVA_CMD = os.environ.get('JAVA_CMD', 'java')

server_files_dir = os.path.join(app.instance_path, 'server')
jar_filename = 'server.jar'
jar_path = os.path.join(server_files_dir, jar_filename)

os.makedirs(server_files_dir, exist_ok=True)

@app.before_request
def ensure_jar_present():
    allowed = {'install', 'upload_jar', 'static', 'jar_status'}
    if not os.path.isfile(jar_path) and request.endpoint not in allowed:
        return redirect(url_for('install'))

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

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
    return jsonify({'folder': server_files_dir, 'expected_jar': jar_filename, 'exists': exists})

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
    global server_process
    if not os.path.isfile(jar_path):
        return
    ver = java_major()
    if ver is None:
        console_output.append('Error: Java not found. Install Java 21+ or set JAVA_CMD.')
        return
    if ver < 21:
        console_output.append(f'Error: Java {ver} detected. This server requires Java 21+. Install Java 21 and set JAVA_CMD or upgrade PATH.')
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
            threading.Thread(target=emit_server_output, args=(server_process,), daemon=True).start()
        except Exception as e:
            console_output.append(f"Server start error: {e}")

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

@app.route('/start')
def start_minecraft_server():
    Thread(target=start_server, daemon=True).start()
    return "Minecraft Server wird gestartet..."

def emit_server_output(process):
    global console_output, players
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

@app.route('/server-status')
def server_status():
    return jsonify({'running': read_server_status()})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5003, host='0.0.0.0')
