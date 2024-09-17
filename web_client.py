# Created by Nemesis
# nemesisuks@protonmail.com

from flask import Flask, request, render_template, jsonify
import socket
import socks
import threading
import base64
from time import time, strftime, localtime
from urllib.parse import urlparse
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from stem import Signal
from stem.control import Controller
import oqs
import hashlib
import secrets
from Crypto.Math.Numbers import Integer

app = Flask(__name__)

# Constants
HISTORY_FILE = "chat_history.txt"
SPAM_INTERVAL = 2  # Time interval (in seconds) to prevent spam

# Define color codes (HTML equivalents)
COLORS = {
    'blue': '#0000FF',
    'green': '#00FF00',
    'red': '#FF0000',
    'yellow': '#FFFF00',
    'magenta': '#FF00FF',
    'cyan': '#00FFFF',
    'white': '#FFFFFF'
}
SYSTEM_COLOR = '#FFFF00'  # Yellow for system messages
color_keys = list(COLORS.keys())

# In-memory storage for chat messages
chat_history = []

def hash_color(username):
    """Hash the username to get a fixed color."""
    hashed_value = int(hashlib.sha256(username.encode()).hexdigest(), 16)
    color_key = color_keys[hashed_value % len(color_keys)]
    return COLORS[color_key]

def color_username(username):
    """Colorizes a username with a fixed color."""
    color = hash_color(username)
    return f"#{color}"

def system_message(message):
    """Format system messages."""
    return f"<span style='color:{SYSTEM_COLOR};'>[SYSTEM] {message}</span>"

def timestamp_message(message):
    """Adds a timestamp to the message."""
    timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime())
    return f"[{timestamp}] {message}"

# Proxy Configuration
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
I2P_SOCKS_PORT = 4444

def setup_tor_proxy():
    """Sets up Tor proxy for .onion domains."""
    socks.set_default_proxy(socks.SOCKS5, "localhost", TOR_SOCKS_PORT)
    socket.socket = socks.socksocket
    control_tor()

def control_tor():
    """Refreshes the Tor circuit to get a new identity."""
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print(system_message("Tor circuit refreshed."))
    except Exception as e:
        print(system_message(f"Error controlling Tor: {e}"))

def setup_i2p_proxy():
    """Sets up I2P proxy for .i2p domains."""
    socks.set_default_proxy(socks.SOCKS5, "localhost", I2P_SOCKS_PORT)
    socket.socket = socks.socksocket

# Encryption functions
def generate_random_key(length):
    return get_random_bytes(length)

def chacha20_poly1305_encrypt(data, key, max_length=1024):
    """Encrypt data and add padding to obscure message length."""
    padding_length = max_length - len(data)
    if padding_length > 0:
        padding = get_random_bytes(padding_length)
    else:
        padding = b''
    
    padded_data = data + padding
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(padded_data)
    return cipher.nonce + tag + ciphertext

def chacha20_poly1305_decrypt(data, key, original_length):
    """Decrypt data and remove padding."""
    nonce, tag, ciphertext = data[:12], data[12:28], data[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    decrypted_padded_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    decrypted_data = decrypted_padded_data[:original_length]
    return decrypted_data

# Key exchange functions
def ecdh_shared_secret(private_key, public_key):
    shared_point = public_key.pointQ * Integer(private_key.d)
    shared_secret = SHA256.new(shared_point.x.to_bytes()).digest()
    return shared_secret

def derive_key(kyber_secret, dh_secret):
    combined_secret = kyber_secret + dh_secret
    return SHA256.new(combined_secret).digest()

@app.route('/fetch')
def fetch():
    return jsonify({'messages': chat_history})

def send_message(conn, key, username, message, max_length=1024):
    try:
        # Format message with username
        message_with_username = f"{username}: {message}".encode()
        original_length = len(message_with_username)
        ciphertext = chacha20_poly1305_encrypt(message_with_username, key, max_length)
        base64_data = base64.b64encode(ciphertext)

        conn.sendall(b'MSG:')
        conn.sendall(len(base64_data).to_bytes(2, 'big'))
        conn.sendall(base64_data)
        conn.sendall(original_length.to_bytes(2, 'big'))

        # Append sent message to chat history
        if message.lower() != "/exit":
            formatted_message = f"<p><span style='color:{color_username(username)};'>{username}:</span> {message.strip()}</p>"
            chat_history.append(timestamp_message(formatted_message))
            if len(chat_history) > 100:
                chat_history.pop(0)

        print("Message sent and appended:", formatted_message)  # Debug print

    except Exception as e:
        print(system_message(f"Error sending message: {e}"))



def start_chat_client(host='localhost', port=12345):
    base_username = input("Enter your username: ").strip()
    user_id = secrets.randbelow(90000) + 10000
    username = f"{base_username}-{user_id}"

    if host.endswith('.onion'):
        print(system_message("Using Tor to connect to .onion address."))
        setup_tor_proxy()
    elif host.endswith('.i2p'):
        print(system_message("Using I2P to connect to .i2p address."))
        setup_i2p_proxy()

    kemalg = "Kyber512"

    with oqs.KeyEncapsulation(kemalg) as kem:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print(system_message("Connecting to server..."))
            sock.connect((host, port))
            print(system_message("Connected to server."))
        except Exception as e:
            print(system_message(f"Connection error: {e}"))
            return

        client_public_key = kem.generate_keypair()
        sock.sendall(client_public_key)

        try:
            ciphertext = sock.recv(1024)
            shared_secret_kyber_client = kem.decap_secret(ciphertext)

            dh_key_client = ECC.generate(curve='P-256')
            dh_public_key_client = dh_key_client.public_key().export_key(format='DER')
            sock.sendall(dh_public_key_client)

            dh_public_key_server = sock.recv(1024)
            dh_key_server = ECC.import_key(dh_public_key_server)
            shared_secret_dh_client = ecdh_shared_secret(dh_key_client, dh_key_server)

            symmetric_key = derive_key(shared_secret_kyber_client, shared_secret_dh_client)
        except Exception as e:
            print(system_message(f"Key exchange error: {e}"))
            return

        def receive_messages():
            while True:
                try:
                    prefix = sock.recv(4)
                    if not prefix:
                        break

                    if prefix == b'MSG:':
                        message_length = int.from_bytes(sock.recv(2), 'big')
                        encrypted_message = sock.recv(message_length)
                        original_length = int.from_bytes(sock.recv(2), 'big')

                        base64_data = base64.b64decode(encrypted_message)
                        decrypted_message = chacha20_poly1305_decrypt(base64_data, symmetric_key, original_length)
                        message = decrypted_message.decode()

                        if message == "DUMMY_DATA":
                            continue

                        if ':' in message:
                            received_username, text = message.split(':', 1)
                            colored_username = color_username(received_username.strip())
                            formatted_message = f"<p><span style='color:{colored_username};'>{received_username}:</span> {text.strip()}</p>"
                        else:
                            formatted_message = f"<p>{message}</p>"

                        # Append received message to chat history
                        chat_history.append(timestamp_message(formatted_message))
                        if len(chat_history) > 100:
                            chat_history.pop(0)

                except Exception as e:
                    print(system_message(f"Error receiving message: {e}"))
                    break


        threading.Thread(target=receive_messages, daemon=True).start()

        @app.route('/')
        def index():
            return render_template('index.html', messages=chat_history, username=username)


        @app.route('/send', methods=['POST'])
        def send():
            message = request.form['message']
            if message.lower() == "/exit":
                send_message(sock, symmetric_key, username, f"{username} has left the chat.")
                return jsonify({'status': 'exit'})
            elif len(message.strip()) == 0:
                return jsonify({'status': 'empty'})

            send_message(sock, symmetric_key, username, f"{message}")
            return jsonify({'status': 'sent'})



        app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # Default server address for testing
    server_host = input("Enter server address (default localhost): ").strip() or "localhost"
    server_port = int(input("Enter server port (default 12345): ").strip() or 12345)
    start_chat_client(host=server_host, port=server_port)
