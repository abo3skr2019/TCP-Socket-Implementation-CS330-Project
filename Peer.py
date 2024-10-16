import threading
import signal
import json
import sys
from Server import Server  # Assuming you have refactored the server into Server.py
from Client import Client  # Assuming you have refactored the client into Client.py

class Peer:
    def __init__(self, server_config: dict, client_config: dict):
        self.server = Server(server_config)
        self.client = Client(client_config)
        self.discoverable = False
        self.shutdown_flag = threading.Event()

    def signal_handler(self, sig, frame):
        """
        Handle shutdown signals (e.g., Ctrl+C).
        """
        print("\nShutting down both server and client...")
        self.shutdown_flag.set()
        self.server.shutdown_flag.set()  # Gracefully shut down the server
        self.client.shutdown_flag.set()  # Gracefully shut down the client
        sys.exit(0)

    def start(self):
        """
        Start both the server and client.
        """
        # Register the signal handler for clean shutdown
        signal.signal(signal.SIGINT, self.signal_handler)

        # Start the server in a separate thread
        server_thread = threading.Thread(target=self.server.start_server)
        server_thread.start()

        # Start the broadcast listener in a separate thread
        if self.discoverable:
            broadcast_listener_thread = threading.Thread(target=self.server.broadcast_listener)
            broadcast_listener_thread.start()

        # Start the client in the main thread or another thread if preferred
        client_thread = threading.Thread(target=self.client.start_client)
        client_thread.start()

        # Join threads to wait for graceful shutdown
        server_thread.join()
        if self.discoverable:
            broadcast_listener_thread.join()
        client_thread.join()

if __name__ == "__main__":
    # Load server and client configurations from JSON files
    try:
        with open('ServerConfig.json', 'r') as server_config_file:
            server_config = json.load(server_config_file)
        with open('ClientConfig.json', 'r') as client_config_file:
            client_config = json.load(client_config_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Create and start the peer application
    peer = Peer(server_config, client_config)
    peer.start()
