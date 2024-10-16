import socket
import threading
import struct
import json
import random
import sys
import signal
import logging
from MiscHelperClasses import ConfigLoader, Logger
from SocketHelperClasses import Checksum

class P2PNode:
    def __init__(self, config_file: str, discoverable: bool = True):
        self.shutdown_flag = threading.Event()
        self.connection_established = threading.Event()
        self.server_socket = None
        self.config_loader = ConfigLoader(config_file)
        self.config = self.config_loader.config  # Load config using ConfigLoader
        self.buffer_size = self.config.get('buffer_size', 1024)
        self.max_connections = self.config.get('max_connections', 5)
        self.default_ip = self.config.get('default_ip', "127.0.0.1")
        self.external_ip_check = self.config.get('external_ip_check', "8.8.8.8")
        self.external_ip_port = self.config.get('external_ip_port', 80)
        self.interface_ip = self.config['network_interface']
        self.broadcast_port = self.config.get('broadcast_port', 37020)
        self.error_simulation_config = self.config.get('error_simulation', {})
        self.error_simulation_enabled = self.error_simulation_config.get('enabled', False)
        self.error_probability = self.error_simulation_config.get('probability', 0.0)
        self.sock = None
        self.discoverable = discoverable
        self.setup_signal_handling()

    def setup_signal_handling(self):
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

    def handle_signal(self, signum, frame):
        print("Signal received, shutting down...")
        self.shutdown_flag.set()
        if self.sock:
            self.sock.close()
        if self.server_socket:
            self.server_socket.close()
        sys.exit(0)

    def introduce_error(self, data, probability):
        if random.random() < probability:
            error_index = random.randint(0, len(data) - 1)
            data = bytearray(data)
            data[error_index] ^= 0xFF
        return bytes(data)

    def receive(self):
        while not self.shutdown_flag.is_set():
            try:
                data = self.sock.recv(1024)
                if data:
                    try:
                        print(f"Received: {data.decode('utf-8')}")
                    except UnicodeDecodeError as e:
                        print(f"Failed to decode received data: {e}")
                else:
                    break
            except Exception as e:
                print(f"You have been disconnected from the server. Exception: {e}")
                break

    def send(self):
        while not self.shutdown_flag.is_set():
            message = input()
            if message.lower() == "quit":
                print("Exiting...")
                self.sock.close()
                break
            if not message:
                print("Error: The entered message is not valid")
                continue

            message_bytes = message.encode('utf-8')
            checksum = Checksum.calculate(message_bytes)
            message_with_checksum = message_bytes + struct.pack('!H', checksum)

            if self.error_simulation_enabled:
                message_with_checksum = self.introduce_error(message_with_checksum, self.error_probability)

            self.sock.sendall(message_with_checksum)

    def get_local_ip_addresses(self):
        ip_addresses = []
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in local_ips:
            if not ip.startswith("127."):
                ip_addresses.append(ip)
        return ip_addresses

    def discover_peers(self):
        def send_broadcast(udp_socket, interface_ip):
            udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udp_socket.settimeout(2)
            udp_socket.bind((interface_ip, 0))
            message = "DISCOVER_PEER".encode('utf-8')
            try:
                udp_socket.sendto(message, ('<broadcast>', self.broadcast_port))
                print(f"Broadcast message sent to port {self.broadcast_port} through interface {interface_ip}")
            except Exception as e:
                print(f"Failed to send broadcast message: {e}")

        if self.interface_ip == "0.0.0.0":
            local_ips = self.get_local_ip_addresses()
            for ip in local_ips:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                send_broadcast(udp_socket, ip)
        else:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_broadcast(udp_socket, self.interface_ip)

        print("Discovering peers on the network...")
        peers = []
        try:
            while True:
                print("Waiting for responses...")
                data, addr = udp_socket.recvfrom(1024)
                print(f"Received response from {addr}")
                peer_info = json.loads(data.decode('utf-8'))
                peers.append((addr[0], peer_info['port']))
        except socket.timeout:
            print("Peer discovery completed")
        except Exception as e:
            print(f"Error receiving response: {e}")

        return peers

    def start_client(self):
        if self.discoverable:
            peers = self.discover_peers()
            if peers:
                print("Discovered peers:")
                for i, (ip, port) in enumerate(peers):
                    print(f"{i + 1}. {ip}:{port}")
                choice = input("Select a peer by number or press Enter to input manually: ")
                if choice.isdigit() and 1 <= int(choice) <= len(peers):
                    peer, port = peers[int(choice) - 1]
                else:
                    peer = input("Peer: ")
                    port = int(input("Port: "))
            else:
                print("No peers discovered.")
                peer = input("Peer: ")
                port = int(input("Port: "))
        else:
            peer = input("Peer: ")
            port = int(input("Port: "))

        if self.connection_established.is_set():
            print("Connection request received, cancelling peer input sequence.")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.interface_ip, 0))
            self.sock.connect((peer, port))
            print("Successfully connected to peer")
            self.connection_established.set()
        except:
            print("Peer is down, please try later.")
            input("Press enter to quit")
            sys.exit(0)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        send_thread = threading.Thread(target=self.send)
        send_thread.start()

        receive_thread.join()
        send_thread.join()

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
        self.connection_established.set()
        self.sock = client_socket

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        send_thread = threading.Thread(target=self.send)
        send_thread.start()

        receive_thread.join()
        send_thread.join()

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
                self.handle_client(client_socket)
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
                if message.decode('utf-8') == "DISCOVER_PEER":
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

def merge_configs(server_config_file, client_config_file, output_file):
    with open(server_config_file, 'r') as f:
        server_config = json.load(f)
    with open(client_config_file, 'r') as f:
        client_config = json.load(f)

    merged_config = {**server_config, **client_config}

    with open(output_file, 'w') as f:
        json.dump(merged_config, f, indent=4)

if __name__ == "__main__":
    logger = Logger.setup_logging()

    # Merge server and client configs into a single P2PConfig.json
    merge_configs('serverConfig.json', 'clientConfig.json', 'P2PConfig.json')

    config_file = 'P2PConfig.json'
    node = P2PNode(config_file)

    broadcast_thread = threading.Thread(target=node.broadcast_listener)
    broadcast_thread.start()

    server_thread = threading.Thread(target=node.start_server)
    server_thread.start()

    node.start_client()

    broadcast_thread.join()
    server_thread.join()