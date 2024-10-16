import json
import logging
import signal
import threading
import sys

class ConfigLoader:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.config = self.load_config()

    def load_config(self) -> dict:
        try:
            with open(self.file_path, 'r') as config_file:
                config = json.load(config_file)
            self.validate_config(config)
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {self.file_path}")
            raise RuntimeError("Failed to load configuration: File not found")
        except ValueError as e:
            logging.error(f"Invalid configuration format: {e}")
            raise RuntimeError("Failed to load configuration: Invalid format")

    def validate_config(self, config: dict) -> None:
        required_keys = ['network_interface', 'broadcast_port']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")

class Logger:
    @staticmethod
    def setup_logging():
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)

        file_handler = logging.FileHandler('app.log')
        console_handler = logging.StreamHandler()

        formatter = logging.Formatter('%(asctime)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger

class SignalHandler:
    def __init__(self, server=None, client=None):
        self.server = server
        self.client = client

    def handle_signal(self, sig: int, frame: any) -> None:
        if self.server:
            logging.info(f"Signal {sig} caught, shutting down the server...")
            self.server.shutdown_flag.set()
            if self.server.server_socket:
                self.server.server_socket.close()
            for thread in threading.enumerate():
                if thread is not threading.current_thread():
                    thread.join()
            logging.info("Server has been shut down gracefully.")
        if self.client:
            logging.info(f"Signal {sig} caught, shutting down the client...")
            if self.client.sock:
                self.client.sock.close()
            sys.exit(0)

    def setup_signal_handling(self):
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
