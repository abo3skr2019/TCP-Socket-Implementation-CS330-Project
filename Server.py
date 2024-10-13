import socket
import threading
import struct
import json
import sys
import signal
from Checksum import validate_checksum
import logging

# Constants
BUFFER_SIZE = 1024
DEFAULT_IP = "127.0.0.1"
EXTERNAL_IP_CHECK = "8.8.8.8"
EXTERNAL_IP_PORT = 80

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

def validate_config(config: dict) -> None:
    """
    Validates the configuration dictionary to ensure all required keys are present.

    Args:
        config (dict): Configuration dictionary.

    Raises:
        ValueError: If any required key is missing.
    """
    required_keys = ['network_interface', 'port', 'broadcast_port']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")
    # Additional validation can be added here

def load_config(file_path: str) -> dict:
    try:
        with open(file_path, 'r') as config_file:
            config = json.load(config_file)
        validate_config(config)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {file_path}")
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from the configuration file: {file_path}")
    except ValueError as e:
        logging.error(f"Configuration validation error: {e}")
    sys.exit(1)

def get_actual_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
        try:
            logging.info("Trying to connect to outside world")
            temp_socket.connect((EXTERNAL_IP_CHECK, EXTERNAL_IP_PORT))
            actual_ip = temp_socket.getsockname()[0]
            logging.info(f"Actual IP address: {actual_ip}")
        except Exception:
            actual_ip = DEFAULT_IP
    return actual_ip

def handle_client(client_socket: socket.socket) -> None:
    while not shutdown_flag.is_set():
        try:
            message = client_socket.recv(BUFFER_SIZE)
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

def setup_socket(socket_type: int, options: list = None, bind_address: tuple = None) -> socket.socket:
    set_socket = socket.socket(socket.AF_INET, socket_type)
    if options:
        for opt in options:
            set_socket.setsockopt(*opt)
    if bind_address:
        set_socket.bind(bind_address)
    return set_socket

def start_server(config: dict) -> None:
    global server_socket
    network_interface = config['network_interface']
    port = config['port']
    server_socket = setup_socket(socket.SOCK_STREAM, bind_address=(network_interface, port))
    server_socket.bind((network_interface, port))
    server_socket.listen(5)
    server_socket.settimeout(1)
    logging.info(f"Server started and listening on {network_interface}:{port}")
    while not shutdown_flag.is_set():
        try:
            client_socket, addr = server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            continue
        except socket.error as e:
            if shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def broadcast_listener(config: dict) -> None:
    logging.info("Broadcast listener started")
    try:
        udp_options = [
        (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
        (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    ]
        udp_socket = setup_socket(socket.SOCK_DGRAM, udp_options, bind_address=("", config['broadcast_port']))
        udp_socket.bind(("", config['broadcast_port']))
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    actual_ip = get_actual_ip() if config['network_interface'] == "0.0.0.0" else config['network_interface']
    
    while not shutdown_flag.is_set():
        try:
            udp_socket.settimeout(1)
            message, addr = udp_socket.recvfrom(BUFFER_SIZE)
            logging.info(f"Received broadcast message: {message.decode('utf-8')} from {addr}")
            if message.decode('utf-8') == "DISCOVER_SERVER":
                response = json.dumps({
                    "network_interface": actual_ip,
                    "port": config['port']
                }).encode('utf-8')
                udp_socket.sendto(response, addr)
        except socket.timeout:
            continue
        except socket.error as e:
            if shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def signal_handler(sig: int, frame:any) -> None:
    logging.info(f"Signal {sig} caught, shutting down the server...")
    shutdown_flag.set()
    if server_socket:
        server_socket.close()
    for thread in threading.enumerate():
        if thread is not threading.current_thread():
            thread.join()

if __name__ == "__main__":
    config = load_config('ServerConfig.json')

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    broadcast_thread = threading.Thread(target=broadcast_listener, args=(config,))
    broadcast_thread.start()
    
    start_server(config)
    broadcast_thread.join()
    logging.info("Server has been shut down gracefully.")