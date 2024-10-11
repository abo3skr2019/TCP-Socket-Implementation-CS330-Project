import socket
import threading
import json
import struct
import random
import sys
from Checksum import calculate_checksum

def introduce_error(data, probability):
    """
    Introduce an error in the data based on the given probability.
    This is used to simulate transmission errors.
    """
    if random.random() < probability:
        error_index = random.randint(0, len(data) - 1)
        data = bytearray(data)
        data[error_index] ^= 0xFF  # Flip bits to introduce error
    return bytes(data)

def receive(sock):
    """
    Continuously receive data from the socket.
    This function runs in a separate thread.
    """
    while True:
        try:
            data = sock.recv(1024)
            print(data.decode("utf-8"))
        except:
            print("You have been disconnected from the server")
            sys.exit(0)
            break

# Load configuration from ClientConfig.json
try:
    with open('ClientConfig.json', 'r') as config_file:
        config = json.load(config_file)
except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Please make sure that the ClientConfig.json file exists")
    input("Press enter to quit")
    sys.exit(1)

interface = config['network_interface']
error_simulation_config = config.get('error_simulation', {})
error_simulation_enabled = error_simulation_config.get('enabled', False)
error_probability = error_simulation_config.get('probability', 0.0)

# Get server address and port from user input
Server = input("Server: ")
port = int(input("Port: "))

# Attempt to connect to the server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((interface, 0))  # Bind to the specified network interface
    sock.connect((Server, port))
except:
    print("Server is down, please try later.")
    input("Press enter to quit")
    sys.exit(0)

# Start a thread to receive data from the server
receive_thread = threading.Thread(target=receive, args=(sock,))
receive_thread.start()

# Main loop to send messages to the server
while True:
    message = input()
    if message.lower() == "quit":
        print("Exiting...")
        sock.close()
        break
    if not message:
        print("Error: The entered message is not valid")
        continue

    # Encode the message and calculate its checksum
    message_bytes = message.encode('utf-8')
    checksum = calculate_checksum(message_bytes)
    message_with_checksum = message_bytes + struct.pack('!H', checksum)

    # Optionally introduce an error for testing purposes
    if error_simulation_enabled:
        message_with_checksum = introduce_error(message_with_checksum, error_probability)

    # Send the message with checksum to the server
    sock.sendall(message_with_checksum)