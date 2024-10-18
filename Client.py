#Client.py
import socket
import threading
import json
import struct
import random
import sys
import logging
import signal
from MiscHelperClasses import ConfigLoader, Logger, SignalHandler
from SocketHelperClasses import Checksum

class Client:
    def __init__(self, config_file: str, discoverable: bool = True):
        self.config_loader = ConfigLoader(config_file)
        self.config = self.config_loader.config  # Load config using ConfigLoader
        self.interface_ip = self.config['network_interface']
        self.error_simulation_config = self.config.get('error_simulation', {})
        self.error_simulation_enabled = self.error_simulation_config.get('enabled', False)
        self.error_probability = self.error_simulation_config.get('probability', 0.0)
        self.broadcast_port = self.config.get('broadcast_port', 37020)
        self.sock = None
        self.discoverable = discoverable
        self.signal_handler = SignalHandler(client=self)
        self.signal_handler.setup_signal_handling()

    def introduce_error(self, data, probability):
        if random.random() < probability:
            error_index = random.randint(0, len(data) - 1)
            data = bytearray(data)
            data[error_index] ^= 0xFF
        return bytes(data)

    def receive(self):
        acknowledgement_utf8 = 'ACK'.encode('utf-8')
        error_acknowledgement_utf = 'Error'.encode('utf-8')

        while True:
            try:
                data = self.sock.recv(1024)
                if not data:
                    logging.error("Server has disconnected.")
                    break
                if data.startswith(acknowledgement_utf8):
                    logging.info(data.decode('utf-8'))
                    continue
                if data.startswith(error_acknowledgement_utf):
                    logging.error(data.decode('utf-8'))
                    continue
                # Extract the message and checksum
                received_checksum = struct.unpack('!H', data[-2:])[0]
                message = data[:-2]
                is_valid_checksum = Checksum.validate(message, received_checksum)
                
                # Validate the checksum
                if is_valid_checksum:
                    self.sock.sendall(b"ACK:Your Message has been received correctly")
                    logging.info("received Server Message correctly")
                    logging.info(f"Server: {message.decode('utf-8')}")
                else:
                    self.sock.sendall(b"Error: The Received Message is not correct")
                    logging.error("Error: The Received Message is not correct")
            except:
                logging.error("You have been disconnected from the server")
                sys.exit(0)
                break

    def get_local_ip_addresses(self):
        ip_addresses = []
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in local_ips:
            if not ip.startswith("127."):
                ip_addresses.append(ip)
        return ip_addresses

    def discover_servers(self):
        def send_broadcast(udp_socket, interface_ip):
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp_socket.settimeout(2)
            udp_socket.bind((interface_ip, 0))
            message = "DISCOVER_SERVER".encode('utf-8')
            try:
                udp_socket.sendto(message, ('<broadcast>', self.broadcast_port))
                logging.info(f"Broadcast message sent to port {self.broadcast_port} through interface {interface_ip}")
            except Exception as e:
                logging.error(f"Failed to send broadcast message: {e}")

        if self.interface_ip == "0.0.0.0":
            local_ips = self.get_local_ip_addresses()
            for ip in local_ips:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                send_broadcast(udp_socket, ip)
        else:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_broadcast(udp_socket, self.interface_ip)

        logging.info("Discovering servers on the network...")
        servers = []
        try:
            while True:
                logging.info("Waiting for responses...")
                data, addr = udp_socket.recvfrom(1024)
                logging.info(f"Received response from {addr}")
                server_info = json.loads(data.decode('utf-8'))
                servers.append((addr[0], server_info['port']))
        except socket.timeout:
            logging.info("Server discovery completed")
        except Exception as e:
            logging.error(f"Error receiving response: {e}")

        return servers

    def start_client(self):
        selected_server, port = self.select_server()
        self.connect_to_server(selected_server, port)
        self.handle_messages()

    def select_server(self):
        if self.discoverable:
            servers = self.discover_servers()
            if servers:
                logging.info("Discovered servers:")
                for i, (ip, port) in enumerate(servers):
                    logging.info(f"{i + 1}. {ip}:{port}")
                choice = input("Select a server by number or press Enter to input manually: ")
                if choice.isdigit() and 1 <= int(choice) <= len(servers):
                    return servers[int(choice) - 1]
                else:
                    return self.manual_server_input()
            else:
                logging.info("No servers discovered.")
                return self.manual_server_input()
        else:
            return self.manual_server_input()

    def manual_server_input(self):
        selected_server = input("Server: ")
        port = int(input("Port: "))
        return selected_server, port

    def connect_to_server(self, selected_server, port):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.interface_ip, 0))
            self.sock.connect((selected_server, port))
            logging.info("Successfully connected to server")
        except:
            logging.error("Server is down, please try later.")
            input("Press enter to quit")
            sys.exit(0)

        signal.signal(signal.SIGINT, self.signal_handler.handle_signal)

    def handle_messages(self):
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        while True:
            message = input("Enter message to send to server: ")
            if message.lower() == "quit":
                logging.info("Exiting...")
                self.sock.close()
                break
            if not message:
                logging.error("The entered message is not empty; an empty message is not valid")
                continue

            message_bytes = message.encode('utf-8')
            checksum = Checksum.calculate(message_bytes)
            message_with_checksum = message_bytes + struct.pack('!H', checksum)

            if self.error_simulation_enabled:
                message_with_checksum = self.introduce_error(message_with_checksum, self.error_probability)
            self.sock.sendall(message_with_checksum)
if __name__ == "__main__":
    logger = Logger.setup_logging()
    config_file = 'ClientConfig.json'
    client = Client(config_file)
    client.start_client()