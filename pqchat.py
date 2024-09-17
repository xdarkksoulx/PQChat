# Created by Nemesis
# nemesisuks@protonmail.com

import socket
import socks  # For I2P and Tor support
import threading
import base64
from time import time, sleep, strftime, localtime
from urllib.parse import urlparse
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Math.Numbers import Integer
from stem import Signal
from stem.control import Controller
import oqs  # Post-quantum library for Kyber key exchange
import hashlib
import os
import secrets

# Constants
HISTORY_FILE = "chat_history.txt"
RESET = '\033[0m'  # Reset to default color
SPAM_INTERVAL = 2  # Time interval (in seconds) to prevent spam

# Define color codes
COLORS = {
    'blue': '\033[94m',
    'green': '\033[92m',
    'red': '\033[91m',
    'yellow': '\033[93m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m'
}
SYSTEM_COLOR = '\033[93m'  # Yellow for system messages
color_keys = list(COLORS.keys())

# Track user activity
user_activity = {}

def hash_color(username):
    """Hash the username to get a fixed color."""
    hashed_value = int(hashlib.sha256(username.encode()).hexdigest(), 16)
    color_key = color_keys[hashed_value % len(color_keys)]
    return COLORS[color_key]

def color_username(username):
    """Colorizes a username with a fixed color."""
    color = hash_color(username)
    return f"{color}{username}{RESET}"

def system_message(message):
    """Format system messages."""
    return f"{SYSTEM_COLOR}[SYSTEM] {message}{RESET}"

def timestamp_message(message):
    """Adds a timestamp to the message."""
    timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime())
    return f"[{timestamp}] {message}"

# Proxy Configuration
TOR_SOCKS_PORT = 9050  # Default port for Tor SOCKS proxy
TOR_CONTROL_PORT = 9051  # Default port for Tor control
I2P_SOCKS_PORT = 4444  # Default port for I2P SOCKS proxy

def setup_tor_proxy():
    """Sets up Tor proxy for .onion domains."""
    socks.set_default_proxy(socks.SOCKS5, "localhost", TOR_SOCKS_PORT)
    socket.socket = socks.socksocket
    control_tor()

def control_tor():
    """Refreshes the Tor circuit to get a new identity."""
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()  # Authenticate with the Tor control port
            controller.signal(Signal.NEWNYM)  # Request a new identity (new circuit)
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
    
    # Remove padding
    decrypted_data = decrypted_padded_data[:original_length]
    return decrypted_data

def write_message_to_history(message):
    with open(HISTORY_FILE, "a") as file:
        file.write(message + "\n")

# Key exchange functions
def ecdh_shared_secret(private_key, public_key):
    shared_point = public_key.pointQ * Integer(private_key.d)  # Scalar multiplication
    shared_secret = SHA256.new(shared_point.x.to_bytes()).digest()  # Hash the x-coordinate to derive the shared secret
    return shared_secret

def derive_key(kyber_secret, dh_secret):
    combined_secret = kyber_secret + dh_secret
    return SHA256.new(combined_secret).digest()  # Create a final symmetric key by hashing the combination

# Handle client connections
def handle_client(conn, addr, clients, keys, clients_lock):
    print(system_message(f"Client {addr} connected."))

    try:
        # Kyber Key Exchange
        kemalg = "Kyber512"
        with oqs.KeyEncapsulation(kemalg) as kem:
            client_public_key = conn.recv(1024)
            ciphertext, shared_secret_kyber_server = kem.encap_secret(client_public_key)
            conn.sendall(ciphertext)

        # ECDH Key Exchange
        dh_key_server = ECC.generate(curve='P-256')
        dh_public_key_server = dh_key_server.public_key().export_key(format='DER')
        conn.sendall(dh_public_key_server)

        dh_public_key_client = conn.recv(1024)
        dh_key_client = ECC.import_key(dh_public_key_client)
        shared_secret_dh_server = ecdh_shared_secret(dh_key_server, dh_key_client)

        # Derive the symmetric key
        symmetric_key = derive_key(shared_secret_kyber_server, shared_secret_dh_server)

        # Save client's connection and symmetric key
        with clients_lock:
            clients.append(conn)
            keys[conn] = symmetric_key

        user_activity[addr] = time()  # Initialize user activity for spam prevention

        # Start dummy traffic thread for the server to send dummy traffic to this client
        threading.Thread(target=send_dummy_traffic, args=(conn, keys[conn]), daemon=True).start()

        # Main loop for receiving messages
        while True:
            prefix = conn.recv(4)
            if not prefix:
                break

            if prefix == b'MSG:':
                message_length = int.from_bytes(conn.recv(2), 'big')
                encrypted_message = conn.recv(message_length)
                original_length = int.from_bytes(conn.recv(2), 'big')

                base64_data = base64.b64decode(encrypted_message)
                decrypted_message = chacha20_poly1305_decrypt(base64_data, symmetric_key, original_length)
                message = decrypted_message.decode()

                # Ignore empty or dummy messages
                if not message or message == "DUMMY_DATA":
                    continue

                current_time = time()
                last_message_time = user_activity.get(addr, 0)
                if current_time - last_message_time < SPAM_INTERVAL:
                    print(system_message(f"Warning: User {addr} is sending messages too quickly. Message ignored."))
                    continue

                user_activity[addr] = current_time

                # Extract username and message
                if ':' in message:
                    username, text = message.split(':', 1)
                    colored_username = color_username(username.strip())
                    formatted_message = f"{colored_username}: {text.strip()}"
                else:
                    formatted_message = message

                print(timestamp_message(formatted_message))
                write_message_to_history(f"Received: {formatted_message}")

                # Broadcast the message to other clients
                with clients_lock:
                    for client_conn in clients:
                        if client_conn != conn:
                            try:
                                send_message(client_conn, keys[client_conn], message)
                            except Exception as e:
                                print(system_message(f"Error sending message to {client_conn.getpeername()}: {e}"))

    finally:
        with clients_lock:
            clients.remove(conn)
            keys.pop(conn, None)
        conn.close()
        print(system_message(f"Client {addr} disconnected."))
        user_activity.pop(addr, None)  # Clean up user activity data



# Send messages
def send_message(conn, key, message, max_length=1024):
    try:
        message_with_username = message.encode()
        original_length = len(message_with_username)
        # Encrypt and pad the message
        ciphertext = chacha20_poly1305_encrypt(message_with_username, key, max_length)
        base64_data = base64.b64encode(ciphertext)

        # Send the message with the original length to handle padding on the other side
        conn.sendall(b'MSG:')
        conn.sendall(len(base64_data).to_bytes(2, 'big'))
        conn.sendall(base64_data)
        conn.sendall(original_length.to_bytes(2, 'big'))  # Send the original length
    except Exception as e:
        print(system_message(f"Error sending message: {e}"))


# Dummy traffic to prevent analysis
def send_dummy_traffic(conn, key, min_interval=20, max_interval=60):
    while True:
        # Generate a random interval between min_interval and max_interval
        interval = secrets.randbelow(max_interval - min_interval + 1) + min_interval
        sleep(interval)  # Wait for the random interval
        
        try:
            dummy_message = "DUMMY_DATA"
            send_message(conn, key, dummy_message)
        except Exception as e:
            print(system_message(f"Error sending dummy traffic: {e}"))
            break

# Server setup
def start_chat_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(system_message(f"Server listening on {host}:{port}"))

    clients = []
    keys = {}
    clients_lock = threading.Lock()

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr, clients, keys, clients_lock), daemon=True).start()

# Chat client
def start_chat_client(host='localhost', port=12345):
    base_username = input("Enter your username: ").strip()
    user_id = secrets.randbelow(90000) + 10000  # Generate a secure random 5-digit identifier
    username = f"{base_username}-{user_id}"  # Final username format

    # Determine if we need to use Tor or I2P
    if host.endswith('.onion'):
        print(system_message("Using Tor to connect to .onion address."))
        setup_tor_proxy()
    elif host.endswith('.i2p'):
        print(system_message("Using I2P to connect to .i2p address."))
        setup_i2p_proxy()

    kemalg = "Kyber512"

    with oqs.KeyEncapsulation(kemalg) as kem:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server (through Tor or I2P if applicable)
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

        # Function to receive messages
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

                        # Ignore dummy messages
                        if message == "DUMMY_DATA":
                            continue

                        # Extract username and message
                        if ':' in message:
                            received_username, text = message.split(':', 1)
                            colored_username = color_username(received_username.strip())
                            formatted_message = f"{colored_username}: {text.strip()}"
                        else:
                            formatted_message = message

                        # Display the message and reprint user's input prompt
                        print(f"\n{timestamp_message(formatted_message)}\n{username}: ", end='', flush=True)

                except Exception as e:
                    print(system_message(f"Error receiving message: {e}"))
                    break

        threading.Thread(target=receive_messages, daemon=True).start()

        # Send dummy traffic at random intervals
        def send_dummy_traffic(min_interval=20, max_interval=60):
            while True:
                interval = secrets.randbelow(max_interval - min_interval + 1) + min_interval
                sleep(interval)
                try:
                    dummy_message = "DUMMY_DATA"
                    send_message(sock, symmetric_key, dummy_message)
                except Exception as e:
                    print(system_message(f"Error sending dummy traffic: {e}"))
                    break

        threading.Thread(target=send_dummy_traffic, daemon=True).start()

        try:
            while True:
                message = input(f"{username}: ")
                if message.lower() == "/exit":
                    send_message(sock, symmetric_key, f"{username}: has left the chat.")
                    break
                elif message.lower() == "/history":
                    with open(HISTORY_FILE, "r") as file:
                        history = file.read()
                        print(f"\nChat History:\n{history}\n{username}: ", end='', flush=True)
                elif message.lower() == "/help":
                    help_text = """
                    Commands:
                    /exit - Leave the chat
                    /history - View chat history
                    /help - Show this help message
                    """
                    print(help_text)
                    print(f"{username}: ", end='', flush=True)
                else:
                    send_message(sock, symmetric_key, f"{username}: {message}")
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            print(system_message("Disconnected from server."))

# Main entry point
if __name__ == "__main__":
    mode = input("Do you want to start the server or the client? (server/client): ").strip().lower()
    if mode == "server":
        host = input("Enter host (default: localhost): ").strip() or "localhost"
        port = int(input("Enter port (default: 12345): ").strip() or 12345)
        start_chat_server(host, port)
    elif mode == "client":
        host = input("Enter host (default: localhost): ").strip() or "localhost"
        port = int(input("Enter port (default: 12345): ").strip() or 12345)
        start_chat_client(host, port)
    else:
        print("Invalid option. Please choose 'server' or 'client'.")
