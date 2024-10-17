import socket
import threading
import json
import struct
import random
import sys
import signal
from Checksum import calculate_checksum

def introduce_error(data, probability):
    """
    Add a random error to the data based on the given probability.
    This helps simulate transmission errors.
    
    Parameters:
    data (bytes): The original data that might get corrupted.
    probability (float): The chance of introducing an error.
    
    Returns:
    bytes: The data, possibly with an error.
    """
    if random.random() < probability:
        error_index = random.randint(0, len(data) - 1)
        data = bytearray(data)
        data[error_index] ^= 0xFF  # Flip bits to introduce error
    return bytes(data)

def receive(sock):
    """
    Keep receiving data from the socket.
    This function runs in a separate thread.
    
    Parameters:
    sock (socket.socket): The socket to receive data from.
    """
    while True:
        try:
            data = sock.recv(1024)
            print(data.decode("utf-8"))
        except:
            print("You have been disconnected from the server")
            sys.exit(0)
            break

def signal_handler(sig, frame):
   """
    Handle the Ctrl+C signal to exit the program gracefully.
    
    Parameters:
    sig (int): The signal number.
    frame (frame object): The current stack frame.
    """
    print("\nExiting...")
    sock.close()
    sys.exit(0)

def get_local_ip_addresses():
    """
    Get all local IP addresses associated with the network interfaces.
    
    Returns:
    list: A list of local IP addresses.
    """
    ip_addresses = []
    hostname = socket.gethostname()
    local_ips = socket.gethostbyname_ex(hostname)[2]
    for ip in local_ips:
        if not ip.startswith("127."):
            ip_addresses.append(ip)
    return ip_addresses

def discover_servers(broadcast_port, interface_ip):
    """
    Find servers on the network by sending a broadcast message.
    
    Parameters:
    broadcast_port (int): The port to send the broadcast message to.
    interface_ip (str): The IP address of the network interface to use.
    
    Returns:
    list: A list of discovered servers as tuples of (IP address, port).
    """

    def send_broadcast(udp_socket, interface_ip):
        """
        Send a broadcast message using the specified network interface.
        
        Parameters:
        udp_socket (socket.socket): The UDP socket for broadcasting.
        interface_ip (str): The IP address of the network interface to use.
        """
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.settimeout(2)
        
        # Bind to the specified IP address
        udp_socket.bind((interface_ip, 0))
        
        message = "DISCOVER_SERVER".encode('utf-8')
        
        try:
            udp_socket.sendto(message, ('<broadcast>', broadcast_port))
            print(f"Broadcast message sent to port {broadcast_port} through interface {interface_ip}")
        except Exception as e:
            print(f"Failed to send broadcast message: {e}")

    if interface_ip == "0.0.0.0":
        local_ips = get_local_ip_addresses()
        for ip in local_ips:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_broadcast(udp_socket, ip)
    else:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_broadcast(udp_socket, interface_ip)

    print("Discovering servers on the network...")
    servers = []
    try:
        while True:
            print("Waiting for responses...")
            data, addr = udp_socket.recvfrom(1024)
            print(f"Received response from {addr}")
            server_info = json.loads(data.decode('utf-8'))
            servers.append((addr[0], server_info['port']))
    except socket.timeout:
        print("Server discovery completed")
    except Exception as e:
        print(f"Error receiving response: {e}")
    
    return servers

# Load configuration from ClientConfig.json
try:
    with open('ClientConfig.json', 'r') as config_file:
        config = json.load(config_file)
except FileNotFoundError as e:
    print(f"Error: {e}")
    print("Please make sure that the ClientConfig.json file exists")
    input("Press enter to quit")
    sys.exit(1)

interface_ip = config['network_interface']
error_simulation_config = config.get('error_simulation', {})
error_simulation_enabled = error_simulation_config.get('enabled', False)
error_probability = error_simulation_config.get('probability', 0.0)
broadcast_port = config.get('broadcast_port', 37020)

# Discover servers
servers = discover_servers(broadcast_port, interface_ip)
if servers:
    print("Discovered servers:")
    for i, (ip, port) in enumerate(servers):
        print(f"{i + 1}. {ip}:{port}")
    choice = input("Select a server by number or press Enter to input manually: ")
    if choice.isdigit() and 1 <= int(choice) <= len(servers):
        Server, port = servers[int(choice) - 1]
    else:
        Server = input("Server: ")
        port = int(input("Port: "))
else:
    print("No servers discovered.")
    Server = input("Server: ")
    port = int(input("Port: "))

# Attempt to connect to the server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((interface_ip, 0))  # Bind to the specified network interface
    sock.connect((Server, port))
    print("Successfully connected to server")
except:
    print("Server is down, please try later.")
    input("Press enter to quit")
    sys.exit(0)

# Register the signal handler for SIGINT
signal.signal(signal.SIGINT, signal_handler)

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