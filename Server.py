import socket
import threading
import struct
import random
import json

def calculate_checksum(data):
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def validate_checksum(data, received_checksum):
    return calculate_checksum(data) == received_checksum

def introduce_error(data, probability):
    if random.random() < probability:
        error_index = random.randint(0, len(data) - 1)
        data = bytearray(data)
        data[error_index] ^= 0xFF
    return data

def handle_client(client_socket):
    while True:
        try:
            message_length = client_socket.recv(2)
            if not message_length:
                break
            message_length = struct.unpack('!H', message_length)[0]
            message = client_socket.recv(message_length)
            if not message:
                break
            received_checksum = struct.unpack('!H', message[-2:])[0]
            message = message[:-2]
            if validate_checksum(message, received_checksum):
                client_socket.sendall(b"Message received correctly")
            else:
                client_socket.sendall(b"Error: The Received Message is not correct")
        except Exception as e:
            print(f"Error: {e}")
            break
    client_socket.close()

def start_server(config):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    with open('ServerConfig.json', 'r') as config_file:
        config = json.load(config_file)
    start_server(config)