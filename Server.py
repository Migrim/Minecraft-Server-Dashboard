from flask import Flask, render_template, send_from_directory, jsonify, request
from flask_socketio import SocketIO
from threading import Thread
import subprocess
import threading
import os
import re
import sys
import time
import requests

app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'), instance_relative_config=True)
app.config['SECRET_KEY'] = 'geheim!'
socketio = SocketIO(app)

console_output = []
players = set()

jar_path = 'instance/server-files' 
server_files_dir = os.path.join(app.instance_path, 'server-files')
jar_file_path = os.path.join(app.instance_path, server_files_dir, 'minecraft_server.jar')
server_process = subprocess.Popen(
    ["java", "-Xmx1024M", "-Xms1024M", "-jar", jar_path, "nogui"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    cwd=server_files_dir
)

@app.route('/download-server')
def download_minecraft_server():
    try:
        minecraft_server_path = os.path.join(app.instance_path, server_files_dir, 'minecraft_server.jar')
        os.makedirs(os.path.dirname(minecraft_server_path), exist_ok=True)
        print(f"Verzeichnis erstellt oder existiert bereits: {os.path.dirname(minecraft_server_path)}")

        url = "https://launcher.mojang.com/v1/objects/f1a0073671057f01aa843443fef34330281333ce/server.jar"
        print(f"Starte Download von: {url}")

        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            block_size = 1024
            progress = 0
            with open(minecraft_server_path, 'wb') as f:
                for data in r.iter_content(block_size):
                    progress += len(data)
                    f.write(data)
                    done = int(50 * progress / total_size)
                    print(f"\rDownload Fortschritt: [{'#' * done}{'.' * (50-done)}] {progress * 100 / total_size:.2f}%", end='')

        print("\nDownload abgeschlossen.")
        return send_from_directory(directory=os.path.dirname(minecraft_server_path), path='minecraft_server.jar', as_attachment=True)

    except Exception as e:
        print(f"Fehler: {e}")
        return "Ein Fehler ist aufgetreten."

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

def start_server():
    global server_process
    jar_path = os.path.join(server_files_dir, 'minecraft_server.jar')

    if not os.path.isfile(jar_path):
        print(f"Fehler: Der Minecraft-Server-JAR-File ist nicht unter {jar_path} vorhanden.")
        return

    if server_process is None or server_process.poll() is not None:
        try:
            print(f"Starte einen neuen Server von {jar_path}")
            server_process = subprocess.Popen(
                ["java", "-Xmx1024M", "-Xms1024M", "-jar", jar_path, "nogui"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=server_files_dir
            )
            threading.Thread(target=emit_server_output, args=(server_process,)).start()
            print("Minecraft Server gestartet.")
        except Exception as e:
            print(f"Fehler beim Starten des Minecraft-Servers: {e}")

@app.route('/send-command', methods=['POST'])
def send_command():
    global server_process
    command = request.json['command'] + '\n'
    try:
        if server_process and server_process.stdin and not server_process.poll():
            print(f"Sending command to server: {command.strip()}")
            server_process.stdin.write(command)
            server_process.stdin.flush()
            console_output.append(f"Command: {command.strip()}") 
            return jsonify({"status": "Command sent"})
        else:
            print("Server not running or input stream closed")
            return jsonify({"error": "Server not running or input stream closed"}), 400
    except Exception as e:
        print(f"Error sending command: {e}")
        return jsonify({"error": str(e)}), 500

def send_server_command(command):
    """
    Sends a command to the Minecraft server's console.

    Parameters:
    command (str): The command to send to the Minecraft server.

    Returns:
    json: A JSON response indicating the status of the command.
    """
    global server_process, console_output
    try:
        if server_process and server_process.stdin and not server_process.poll():
            command_with_newline = f'{command}\n'
            print(f"Sending command to server: {command.strip()}")
            server_process.stdin.write(command_with_newline)
            server_process.stdin.flush()
            console_output.append(f"Command: {command.strip()}")
            return jsonify({"status": "Command sent", "command": command.strip()})
        else:
            print("Server not running or input stream closed")
            return jsonify({"error": "Server not running or input stream closed"}), 400
    except Exception as e:
        print(f"Error sending command: {e}")
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
    thread = Thread(target=start_server)
    thread.start()
    return "Minecraft Server wird gestartet..."

def emit_server_output(process):
    global console_output, players
    for line in iter(process.stdout.readline, ''):

        line_display = line.replace('<', 'ඞ').replace('>', 'ඞ')

        print(f"Console Output: {line_display}")  
        console_output.append(line_display)
        socketio.emit('server_output', {'data': line_display})
        
        join_match = re.search(r"\[Server thread/INFO\]: (\w+) joined the game", line)
        if join_match:
            player_joined = join_match.group(1)
            print(f"Player Joined: {player_joined}")  
            players.add(player_joined)
        
        leave_match = re.search(r"\[Server thread/INFO\]: (\w+) left the game", line)
        if leave_match:
            player_left = leave_match.group(1)
            print(f"Player Left: {player_left}")  
            players.discard(player_left)
        
        if "Stopping server" in line:
            print("Server Stopping. Clearing player list.")  
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
        with open(eula_file_path, 'r') as file:
            content = file.readlines()

        updated_content = [line.replace('eula=false', 'eula=true') for line in content]

        with open(eula_file_path, 'w') as file:
            file.writelines(updated_content)

        print("EULA accepted.")
        return "EULA accepted."
    except Exception as e:
        print(f"Fehler: {e}")
        return "Ein Fehler ist aufgetreten."

@app.route('/stop')
def stop_minecraft_server():
    global server_process
    if server_process is not None and server_process.stdin:
        print("Starting countdown for server shutdown.")
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
            server_process.communicate(timeout=10)
        except Exception as e:
            print(f"Error during server shutdown: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            server_process = None
        return "Minecraft Server gestoppt."
    else:
        print("Minecraft Server läuft nicht, kann nicht gestoppt werden.")
        return "Minecraft Server läuft nicht."

if __name__ == '__main__':
    socketio.run(app, debug=False, port=7440, host='0.0.0.0')
