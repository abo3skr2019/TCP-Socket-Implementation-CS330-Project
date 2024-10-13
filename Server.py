import socket
import threading
import struct
import json
import sys
import signal
from Checksum import validate_checksum
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler('Server.log')
file_handler.setLevel(logging.INFO)

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

shutdown_flag = threading.Event()
server_socket = None

def validate_config(config):
    required_keys = ['network_interface', 'port', 'broadcast_port']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

try:
    with open('ServerConfig.json', 'r') as config_file:
        config = json.load(config_file)
    validate_config(config)
except (FileNotFoundError, ValueError) as e:
    logging.error(f"Error: {e}")
    sys.exit(1)

def get_actual_ip():
    # Create a temporary socket to get the actual IP address
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        logging.info("Trying to connect to outside world")
        # Connect to an external address; doesn't have to be reachable
        temp_socket.connect(("8.8.8.8", 80))
        actual_ip = temp_socket.getsockname()[0]
    except Exception:
        actual_ip = "127.0.0.1"  # Fallback to localhost if unable to determine
    finally:
        temp_socket.close()
    return actual_ip

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
                logging.info(f"Received message: {message.decode('utf-8')}")
            else:
                client_socket.sendall(b"Error: The Received Message is not correct")
        except Exception as e:
            logging.error(f"Error: {e}")
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
    logging.info(f"Server started and listening on {network_interface}:{port}")
    while not shutdown_flag.is_set():
        try:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            continue  # Continue the loop if accept times out
        except socket.error as e:
            if shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def broadcast_listener(config):
    logging.info("Broadcast listener started")
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.bind(("", config['broadcast_port']))
    except socket.error as e:
        logging.error(f"Socket error: {e}") 
    actual_ip = get_actual_ip() if config['network_interface'] == "0.0.0.0" else config['network_interface']
    
    while not shutdown_flag.is_set():
        try:
            udp_socket.settimeout(1)  # Set a timeout for the recvfrom call
            message, addr = udp_socket.recvfrom(1024)
            logging.info(f"Received broadcast message: {message.decode('utf-8')} from {addr}")
            if message.decode('utf-8') == "DISCOVER_SERVER":
                response = json.dumps({
                    "network_interface": actual_ip,
                    "port": config['port']
                }).encode('utf-8')
                udp_socket.sendto(response, addr)
        except socket.timeout:
            continue  # Continue the loop if recvfrom times out
        except socket.error as e:
            if shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def signal_handler(sig, frame):
    logging.info(f"Signal {sig} caught, shutting down the server...")
    shutdown_flag.set()
    if server_socket:
        server_socket.close()
    for thread in threading.enumerate():
        if thread is not threading.current_thread():
            thread.join()

if __name__ == "__main__":
    try:
        with open('ServerConfig.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError as e:
        logging.error(f"Error: {e}")
        logging.error("Please make sure that the ServerConfig.json file exists")
        input("Press enter to quit")
        sys.exit(1)

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the broadcast listener in a separate thread
    broadcast_thread = threading.Thread(target=broadcast_listener, args=(config,))
    broadcast_thread.start()
    
    start_server(config)
    broadcast_thread.join()
    logging.info("Server has been shut down gracefully.")