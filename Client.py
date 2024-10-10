import socket
import threading
import json
import struct
import random
import sys

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

def introduce_error(data, probability):
    if random.random() < probability:
        error_index = random.randint(0, len(data) - 1)
        data = bytearray(data)
        data[error_index] ^= 0xFF  # Flip bits to introduce error
    return bytes(data)

def receive(sock):
    while True:
        try:
            data = sock.recv(1024)
            print(data.decode("utf-8"))
        except:
            print("You have been disconnected from the server")
            break

# Load configuration from config.json
with open('ClientConfig.json', 'r') as config_file:
    config = json.load(config_file)

interface = config['network_interface']

host = input("Client: ")
port = int(input("Port: "))

# Attempt connection to server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((interface, 0))  # Bind to the specified interface
    sock.connect((host, port))
except:
    print("Server is down, please try later.")
    input("Press enter to quit")
    sys.exit(0)

receiveThread = threading.Thread(target=receive, args=(sock,))
receiveThread.start()

while True:
    message = input()
    if message.lower() == "quit":
        print("Exiting...")
        sock.close()
        break
    if not message:
        print("Error: The entered message is not valid")
        continue
    message_bytes = message.encode('utf-8')
    checksum = calculate_checksum(message_bytes)
    message_with_checksum = message_bytes + struct.pack('!H', checksum)
    error_probability = random.choice([0.3, 0.5, 0.8])
    message_with_checksum = introduce_error(message_with_checksum, error_probability)
    sock.sendall(message_with_checksum)