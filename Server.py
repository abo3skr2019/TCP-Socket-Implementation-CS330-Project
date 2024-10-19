import socket
import threading
import struct
import json
import logging
from queue import Queue, Empty
from MiscHelperClasses import ConfigLoader, Logger, SignalHandler
from SocketHelperClasses import Checksum
from threading import Condition

class Server:
    def __init__(self, config_file: dict):
        """
        Initialize the Server object
       
        parameters:
            config_file: The path to the configuration file
        """

        self.shutdown_flag = threading.Event()
        self.server_socket = None
        self.config_loader = ConfigLoader(config_file)
        self.config = self.config_loader.config  # Load config using ConfigLoader
        self.buffer_size = self.config.get('buffer_size', 1024)
        self.max_connections = self.config.get('max_connections', 5)
        self.default_ip = self.config.get('default_ip', "127.0.0.1")
        self.external_ip_check = self.config.get('external_ip_check', "8.8.8.8")
        self.external_ip_port = self.config.get('external_ip_port', 80)
        self.signal_handler = SignalHandler(server=self)
        self.signal_handler.setup_signal_handling()
        self.client_socket = None
        self.message_queue = Queue()
        self.ack_condition = Condition()

    @staticmethod
    def get_actual_ip(default_ip: str, external_ip_check: str, external_ip_port: int) -> str:
        """
        Get the actual IP address of the server through trying to connect to an external IP address
        
        parameters:
            (default_ip): The default IP address to use if the actual IP cannot be determined
            (external_ip_check): The external IP address to check
            (external_ip_port): The port to check the external IP address
        return:
            The actual IP address of the server
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

        Handle the client connection by receiving and processing messages
        
        parameters:
            (client_socket): The client socket object
        """
        self.client_socket = client_socket
        while not self.shutdown_flag.is_set():
            try:
                message = self.receive_message(client_socket)
                if message is None:
                    break
                self.process_message(message)
            except(socket.error) as e:
                logging.error(f"Socket error: {e}")
                break
            except struct.error as e:
                logging.error(f"Struct error: {e}")
                break
            except Exception as e:
                logging.error(f"Unexpected Error encountered: {e}")
                break

        client_socket.close()

    def receive_message(self, client_socket: socket.socket) -> bytes:
        """
        Receive a message from the client

        parameters:
            client_socket: The client socket object
        return: 
            The received message
        """
        message = client_socket.recv(self.buffer_size)
        return message if message else None

    def process_message(self, message: bytes) -> None:
        """
        Process the received message and place it in the message queue
        parameters:
            (message): The received message
        """
        acknowledgement_utf8 = 'ACK:'.encode('utf-8')
        error_acknowledgement_utf = 'Error:'.encode('utf-8')

        if message.startswith(acknowledgement_utf8):
            logging.info("Received ACK from client")
            with self.ack_condition:
                self.ack_condition.notify()
            return
        if message.startswith(error_acknowledgement_utf):
            logging.error("Received Error from client")
            with self.ack_condition:
                self.ack_condition.notify()
            return

        received_checksum = struct.unpack('!H', message[-2:])[0]
        message_body = message[:-2]
        if Checksum.validate(message_body, received_checksum):
            self.message_queue.put(b"ACK:Your Message has been received correctly")
            logging.info(f"Client: {message_body.decode('utf-8')}")
        else:
            self.message_queue.put(b"Error: The Received Message is not correct")
            logging.info("Error: The Received Message is not correct")
        with self.ack_condition:
            self.ack_condition.notify()
    def send_message_to_client(self):
        """
        gets a message from the queue and sends it to the client
        """
        while not self.shutdown_flag.is_set() and self.client_socket:
            try:
                # Check for messages in the queue
                try:
                    message = self.message_queue.get(timeout=1)
                    if message:
                        self.client_socket.sendall(message)
                except Empty:
                    pass
            except Exception as e:
                logging.error(f"Error sending message to client: {e}")

    def handle_user_input(self):
        """
        Handle user input to send to the client this runs in a separate thread to avoid blocking the main thread
        it also is notified when an ACK is received from the client 
        """
        while not self.shutdown_flag.is_set() and self.client_socket:
            try:
                with self.ack_condition:
                    self.ack_condition.wait()  # Wait for the log messages to be printed
                    user_message = input("Enter message to send to client: ")
                    if user_message.lower() == "quit":
                        break
                    if not user_message:
                        logging.error("The entered message is empty; an empty message is not valid")
                    else:
                        message_bytes = user_message.encode('utf-8')
                        checksum = Checksum.calculate(message_bytes)
                        message_with_checksum = message_bytes + struct.pack('!H', checksum)
                        self.message_queue.put(message_with_checksum)
                        self.ack_condition.notify()  # Notify after the user input is handled
            except Exception as e:
                logging.error(f"Error handling user input: {e}")
    @staticmethod
    def setup_socket(socket_type: int, options: list = None, bind_address: tuple = None) -> socket.socket:
        """
        Setup a socket with the specified options

        parameters:
            socket_type: The type of socket to create
            options: The options to set on the socket
            bind_address: The address to bind the socket to

        return: 
            The created socket object
        """
        set_socket = socket.socket(socket.AF_INET, socket_type)
        if options:
            for opt in options:
                set_socket.setsockopt(*opt)
        if bind_address:
            set_socket.bind(bind_address)
        return set_socket

    def start_server(self) -> None:

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
                send_thread = threading.Thread(target=self.send_message_to_client)
                send_thread.start()
                input_thread = threading.Thread(target=self.handle_user_input)
                input_thread.start()
            except socket.timeout:
                continue
            except socket.error as e:
                if self.shutdown_flag.is_set():
                    break
                logging.error(f"Socket error: {e}")

    def broadcast_listener(self) -> None:
        """
        Listen for broadcast messages from clients and respond with the server details    
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

if __name__ == "__main__":
    logger = Logger.setup_logging()
    config_file = 'ServerConfig.json'

    server = Server(config_file)

    broadcast_thread = threading.Thread(target=server.broadcast_listener)
    broadcast_thread.start()

    server.start_server()
    broadcast_thread.join()