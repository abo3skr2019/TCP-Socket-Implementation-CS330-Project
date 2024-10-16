# peer.py
import threading
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from MiscHelperClasses import Logger
from Server import Server
from Client import Client
from MiscHelperClasses import SignalHandler

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

        with ThreadPoolExecutor(max_workers=3) as executor:
            # Start the server in a separate thread
            executor.submit(self.server.start_server)

            # Start the broadcast listener in a separate thread if discoverable
            if self.server_discoverable:
                executor.submit(self.server.broadcast_listener)

            # Start the client in a separate thread
            executor.submit(self.client.start_client)

if __name__ == "__main__":
    logger = Logger.setup_logging()
    server_config_file = 'ServerConfig.json'
    client_config_file = 'ClientConfig.json'

    # Create and start the peer application
    peer = Peer(server_config_file, client_config_file, server_discoverable=False, client_discoverable=True)

    peer.start()