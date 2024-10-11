import socket
import threading
import struct
import json
import sys
from Checksum import validate_checksum

def handle_client(client_socket):
    while True:
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

def start_server(config, server_socket):
    network_interface = config['network_interface']
    port = config['port']
    server_socket.bind((network_interface, port))
    server_socket.listen(5)
    print(f"Server started and listening on {network_interface}:{port}")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


if __name__ == "__main__":
    try:
        with open('ServerConfig.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please make sure that the ServerConfig.json file exists")
        input("Press enter to quit")
        sys.exit(1)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    start_server(config, server_socket)