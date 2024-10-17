import socket
import threading
import struct
import json
import sys
import signal
import logging
from MiscHelperClasses import ConfigLoader,Logger,SignalHandler
from SocketHelperClasses import Checksum


class Server:
    def __init__(self, config_file: dict):
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


    @staticmethod
    def get_actual_ip(default_ip: str, external_ip_check: str, external_ip_port: int) -> str:
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
        self.client_socket = client_socket
        while not self.shutdown_flag.is_set():
            try:
                message = client_socket.recv(self.buffer_size)
                if not message:
                    break
                received_checksum = struct.unpack('!H', message[-2:])[0]
                message = message[:-2]
                if Checksum.validate(message, received_checksum):
                    logging.info(f"Checksum.validate = {Checksum.validate(message, received_checksum)}")
                    client_socket.sendall(b"ACK:Your Message has been received correctly")
                    logging.info("Recieved Client Message correctly")
                    logging.info(f"Client: {message.decode('utf-8')}")
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

    def send_message_to_client(self):
        while not self.shutdown_flag.is_set() and self.client_socket:
            message = input("Enter message to send to client: ")
            if message.lower() == "quit":
                break
            if not message:
                logging.error("Error: Entered Message is Empty. Messages Aren't Valid")
            if self.client_socket:
                try:
                    message_bytes = message.encode('utf-8')
                    checksum = Checksum.calculate(message_bytes)
                    message_with_checksum = message_bytes + struct.pack('!H', checksum)
                    self.client_socket.sendall(message_with_checksum)
                except Exception as e:
                    logging.error(f"Error sending message to client: {e}")

    @staticmethod
    def setup_socket(socket_type: int, options: list = None, bind_address: tuple = None) -> socket.socket:
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

            except socket.timeout:
                continue
            except socket.error as e:
                if self.shutdown_flag.is_set():
                    break
                logging.error(f"Socket error: {e}")

    def broadcast_listener(self) -> None:
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
    config_file ='ServerConfig.json'

    server = Server(config_file)

    broadcast_thread = threading.Thread(target=server.broadcast_listener)
    broadcast_thread.start()

    server.start_server()
    broadcast_thread.join()

