# peer.py
import threading
import json
import sys
from MiscHelperClasses import Logger
from Server import Server  # Assuming you have refactored the server into Server.py
from Client import Client  # Assuming you have refactored the client into Client.py
from MiscHelperClasses import SignalHandler  # Import the SignalHandler class

class Peer:
    def __init__(self, server_config: dict, client_config: dict, server_discoverable: bool = False, client_discoverable: bool = True):
        if server_discoverable and client_discoverable:
            raise ValueError("Both server_discoverable and client_discoverable cannot be True at the same time.")
        
        self.server = Server(server_config)
        self.client = Client(client_config, discoverable=client_discoverable)
        self.server_discoverable = server_discoverable
        self.shutdown_flag = threading.Event()
        
        # Initialize SignalHandler with the server and client
        self.signal_handler = SignalHandler(server=self.server, client=self.client)

    def start(self):
        """
        Start both the server and client.
        """
        # Register the signal handler for clean shutdown
        self.signal_handler.setup_signal_handling()

        # Start the server in a separate thread
        server_thread = threading.Thread(target=self.server.start_server)
        server_thread.start()

        # Start the broadcast listener in a separate thread
        if self.server_discoverable:
            broadcast_listener_thread = threading.Thread(target=self.server.broadcast_listener)
            broadcast_listener_thread.start()

        # Start the client in the main thread or another thread if preferred
        client_thread = threading.Thread(target=self.client.start_client)
        client_thread.start()

        # Join threads to wait for graceful shutdown
        server_thread.join()
        if self.server_discoverable:
            broadcast_listener_thread.join()
        client_thread.join()

if __name__ == "__main__":
    logger = Logger.setup_logging()
    server_config_file ='ServerConfig.json'
    client_config_file = 'ClientConfig.json'

    # Create and start the peer application
    peer = Peer(server_config_file, client_config_file, server_discoverable=False, client_discoverable=True)  # Set server_discoverable and client_discoverable as needed

    peer.start()
