#Client.py
import socket
import threading
import json
import struct
import random
import sys
import signal
from MiscHelperClasses import ConfigLoader,Logger,SignalHandler
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
        while True:
            try:
                data = self.sock.recv(1024)
                print(data.decode("utf-8"))
            except:
                print("You have been disconnected from the server")
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

    def start_client(self):
        if self.discoverable:
            servers = self.discover_servers()
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
        else:
            Server = input("Server: ")
            port = int(input("Port: "))

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.interface_ip, 0))
            self.sock.connect((Server, port))
            print("Successfully connected to server")
        except:
            print("Server is down, please try later.")
            input("Press enter to quit")
            sys.exit(0)

        signal.signal(signal.SIGINT, self.signal_handler)

        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

        while True:
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

if __name__ == "__main__":
    logger = Logger.setup_logging()
    config_file = 'ClientConfig.json'
    client = Client(config_file)
    client.start_client()