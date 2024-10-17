import socket
import threading
import struct
import json
import sys
import signal
from Checksum import validate_checksum
import logging



def setup_logging():
   """
      Set up a socket with the given options and bind address.
        
        Parameters:
        socket_type (int): The type of socket (e.g., socket.SOCK_STREAM).
        options (list): List of socket options to set.
        bind_address (tuple): Address to bind the socket to.
        
        Returns:
      socket.socket: Configured socket.
        """   

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler('Server.log')
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

logger = setup_logging()

class Server:
        """
        Initialize the server with the given configuration.
        
        Parameters:
        config (dict): Configuration dictionary.
        """

    def __init__(self, config: dict):
         """
        Initialize the server with the given configuration.
        
        Parameters:
        config (dict): Configuration dictionary.
        """
        
        self.shutdown_flag = threading.Event()
        self.server_socket = None
        self.config = config
        self.buffer_size = config.get('buffer_size', 1024)
        self.max_connections = config.get('max_connections', 5)
        self.default_ip = config.get('default_ip', "127.0.0.1")
        self.external_ip_check = config.get('external_ip_check', "8.8.8.8")
        self.external_ip_port = config.get('external_ip_port', 80)

    @staticmethod
    def validate_config(config: dict) -> None:
         """
        Validate the server configuration.
        
        Parameters:
        config (dict): Configuration dictionary.
        
        Raises:
        ValueError: If a required configuration key is missing.
        """

        required_keys = ['network_interface', 'port', 'broadcast_port']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")

    @staticmethod
    def load_config(file_path: str) -> dict:
         """
        Load the server configuration from a file.
        
        Parameters:
        file_path (str): Path to the configuration file.
        
        Returns:
        dict: Loaded configuration dictionary.
        
        Raises:
        RuntimeError: If the configuration file is not found or invalid.
        """

        try:
            with open(file_path, 'r') as config_file:
                config = json.load(config_file)
            Server.validate_config(config)
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {file_path}")
            raise RuntimeError("Failed to load configuration: File not found")
        except ValueError as e:
            logging.error(f"Invalid configuration format: {e}")
            raise RuntimeError("Failed to load configuration: Invalid format")

    @staticmethod
    def get_actual_ip(default_ip: str, external_ip_check: str, external_ip_port: int) -> str:
        
         """
        Get the actual IP address of the server.
        
        Parameters:
        default_ip (str): Default IP address to use if external check fails.
        external_ip_check (str): External IP check address.
        external_ip_port (int): External IP check port.
        
        Returns:
        str: Actual IP address.
        """

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            try:
                logging.info("Trying to connect to outside world")
                temp_socket.connect((external_ip_check, external_ip_port))
                actual_ip = temp_socket.getsockname()[0]
                logging.info(f"Actual IP address: {actual_ip}")
            except Exception:
                actual_ip = default_ip
        return actual_ip

    def handle_client(self, client_socket: socket.socket) -> None:

        """
        Handle communication with a connected client.
        
        Parameters:
        client_socket (socket.socket): The client socket.
        """

        while not self.shutdown_flag.is_set():
            try:
                message = client_socket.recv(self.buffer_size)
                if not message:
                    break
                received_checksum = struct.unpack('!H', message[-2:])[0]
                message = message[:-2]
                if validate_checksum(message, received_checksum):
                    client_socket.sendall(b"Message received correctly")
                    logging.info(f"Received message: {message.decode('utf-8')}")
                else:
                    client_socket.sendall(b"Error: The Received Message is not correct")
            except socket.error as e:
                logging.error(f"Socket error: {e}")
                break
            except struct.error as e:
                logging.error(f"Struct error: {e}")
                break
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                break

        client_socket.close()

    @staticmethod
    def setup_socket(socket_type: int, options: list = None, bind_address: tuple = None) -> socket.socket:

        """
        Set up a socket with the given options and bind address.
        
        Parameters:
        socket_type (int): The type of socket (e.g., socket.SOCK_STREAM).
        options (list): List of socket options to set.
        bind_address (tuple): Address to bind the socket to.
        
        Returns:
        socket.socket: Configured socket.
        """

        set_socket = socket.socket(socket.AF_INET, socket_type)
        if options:
            for opt in options:
                set_socket.setsockopt(*opt)
        if bind_address:
            set_socket.bind(bind_address)
        return set_socket

def start_server(self) -> None:
    """
    Start the server and listen for incoming connections.
    """
    network_interface = self.config['network_interface']
    port = self.config['port']
    
    self.server_socket = self.setup_socket(socket.SOCK_STREAM, bind_address=(network_interface, port))
    self.server_socket.listen(self.max_connections)
    self.server_socket.settimeout(1)
    logging.info(f"Server started and listening on {network_interface}:{port}")
    
    while not self.shutdown_flag.is_set():
        try:
            
            client_socket, addr = self.server_socket.accept()
            logging.info(f"Accepted connection from {addr}")
            
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()
        except socket.timeout:
            continue
        except socket.error as e:
            if self.shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def broadcast_listener(self) -> None:
    """
    Listen for broadcast messages and respond with server details.
    """
    logging.info("Broadcast listener started")
    try:
        udp_options = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        ]
        
        udp_socket = self.setup_socket(socket.SOCK_DGRAM, udp_options, bind_address=("", self.config['broadcast_port']))
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    
    if self.config['network_interface'] == "0.0.0.0":
        actual_ip = self.get_actual_ip(self.default_ip, self.external_ip_check, self.external_ip_port)
    else:
        actual_ip = self.config['network_interface']

    while not self.shutdown_flag.is_set():
        try:
            udp_socket.settimeout(1)
            
            message, addr = udp_socket.recvfrom(self.buffer_size)
            logging.info(f"Received broadcast message: {message.decode('utf-8')} from {addr}")
            if message.decode('utf-8') == "DISCOVER_SERVER":
                
                response = json.dumps({
                    "network_interface": actual_ip,
                    "port": self.config['port']
                }).encode('utf-8')
                udp_socket.sendto(response, addr)
        except socket.timeout:
            continue
        except socket.error as e:
            if self.shutdown_flag.is_set():
                break
            logging.error(f"Socket error: {e}")

def signal_handler(self, sig: int, frame: any) -> None:
    """
    Handle shutdown signals to gracefully stop the server.
    
    Parameters:
    sig (int): Signal number.
    frame (any): Current stack frame.
    """
    logging.info(f"Signal {sig} caught, shutting down the server...")
    self.shutdown_flag.set()
    if self.server_socket:
        self.server_socket.close()
    for thread in threading.enumerate():
        if thread is not threading.current_thread():
            thread.join()
    logging.info("Server has been shut down gracefully.")

if _name_ == "_main_":

    config = Server.load_config('ServerConfig.json')

    server = Server(config)
    
    signal.signal(signal.SIGINT, server.signal_handler)
    signal.signal(signal.SIGTERM, server.signal_handler)

 
    broadcast_thread = threading.Thread(target=server.broadcast_listener)
    broadcast_thread.start()

    server.start_server()
    broadcast_thread.join()
    logging.info("Server has been shut down gracefully.")