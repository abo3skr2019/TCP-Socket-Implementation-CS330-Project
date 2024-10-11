import socket
import threading
import struct
import json
import sys
import signal
from Checksum import validate_checksum

shutdown_flag = threading.Event()
server_socket = None

def handle_client(client_socket):
    while not shutdown_flag.is_set():
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            received_checksum = struct.unpack('!H', message[-2:])[0]
            message = message[:-2]
            if validate_checksum(message, received_checksum):
                client_socket.sendall(b"Message received correctly")
                print(f"Received message: {message.decode('utf-8')}")
            else:
                client_socket.sendall(b"Error: The Received Message is not correct")
        except Exception as e:
            print(f"Error: {e}")
            break
    client_socket.close()

def start_server(config):
    global server_socket
    network_interface = config['network_interface']
    port = config['port']
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((network_interface, port))
    server_socket.listen(5)
    server_socket.settimeout(1)  # Set a timeout for the accept call
    print(f"Server started and listening on {network_interface}:{port}")
    while not shutdown_flag.is_set():
        try:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            continue  # Continue the loop if accept times out
        except socket.error as e:
            if shutdown_flag.is_set():
                break
            print(f"Socket error: {e}")

def signal_handler(sig, frame):
    print(f"Signal {sig} caught, shutting down the server...")
    shutdown_flag.set()
    if server_socket:
        server_socket.close()

if __name__ == "__main__":
    try:
        with open('ServerConfig.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure that the ServerConfig.json file exists")
        input("Press enter to quit")
        sys.exit(1)

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    start_server(config)
    print("Server has been shut down gracefully.")