import socket
import struct
import logging
import random
class Checksum:
    @staticmethod
    def calculate(data):
        """

            Calculate the checksum for the given data.
            This helps ensure the data hasn't been corrupted.

            Parameters:
            data (bytes): The data you want to check.

            Returns:
            int: The calculated checksum.
        """
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) + data[i + 1]
            else:
                word = data[i] << 8
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF

    @staticmethod
    def validate(data, received_checksum):
        """

            Check if the checksum for the given data is correct.

            Parameters:
            data (bytes): The data you want to validate.
            received_checksum (int): The checksum that came with the data.

            Returns:
            bool: True if the checksum is correct, False otherwise.
        """
        return Checksum.calculate(data) == received_checksum


class SocketHelper:
    @staticmethod
    def setup_socket(socket_type: int, options: list = None, bind_address: tuple = None) -> socket.socket:
        """
        Sets up a socket of the given type with specified options and binding address.
        """
        set_socket = socket.socket(socket.AF_INET, socket_type)
        if options:
            for opt in options:
                set_socket.setsockopt(*opt)
        if bind_address:
            set_socket.bind(bind_address)
        return set_socket

class ConnectionManager:
    def __init__(self, config):
        self.buffer_size = config.get['buffer_size']
        self.error_simulation_enabled = config.get['error_simulation_enabled']
        self.error_probability = config.get['error_probability']
        network_interface = config.get['network_interface']
        port = config.get['port']
        self.server_socket = SocketHelper.setup_socket(socket.SOCK_STREAM, bind_address=(network_interface, port))


    def introduce_error(self, data):
        if self.error_simulation_enabled and random.random() < self.error_probability:
            error_index = random.randint(0, len(data) - 1)
            data = bytearray(data)
            data[error_index] ^= 0xFF
            return bytes(data)
        return data

    def send_message(self, message):
        message_bytes = message.encode('utf-8')
        checksum = Checksum.calculate(message_bytes)
        message_with_checksum = message_bytes + struct.pack('!H', checksum)

        if self.error_simulation_enabled:
            message_with_checksum = self.introduce_error(message_with_checksum)

        self.sock.sendall(message_with_checksum)

    def receive_message(self):
        try:
            data = self.sock.recv(self.buffer_size)
            return data.decode("utf-8")
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            return None

    def close_connection(self):
        if self.sock:
            self.sock.close()
