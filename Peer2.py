# client.py
import socket
import threading
import random

# Function to calculate checksum
def calculate_checksum(message):
    checksum = sum(bytearray(message, 'utf-8')) % 65536
    return ~checksum & 0xFFFF  # 16-bit one's complement

# Function to simulate errors in messages
def simulate_error(message, error_probability):
    if random.random() < error_probability:
        return message + "ERROR"
    return message

def handle_server_messages(server_socket):
    while True:
        try:
            received_data = server_socket.recv(1024).decode('utf-8')
            if not received_data:
                break
            
            # Extracting message and checksum
            message, received_checksum = received_data[:-5], int(received_data[-5:])
            calculated_checksum = calculate_checksum(message)
            
            # Check checksum for actual messages only
            if not message.startswith("ACK") and calculated_checksum != received_checksum:
                print("Error: The Received Message is not correct.")
            else:
                if message.startswith("ACK"):
                    print(f"Acknowledgment received: {message}")
                else:
                    print(f"Server says: {message}")
                    # Send acknowledgment back to the server
                    ack_message = "ACK: Message received"
                    ack_checksum = calculate_checksum(ack_message)
                    server_socket.send(f"{ack_message}{ack_checksum:05}".encode())

        except Exception as e:
            print("Error receiving message:", e)
            break

def start_client(ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ip, port))
    except ConnectionRefusedError:
        print("Server is down, please try later.")
        return

    threading.Thread(target=handle_server_messages, args=(client_socket,)).start()

    while True:
        message = input("Enter message to send (type 'Quit' to exit): ")
        if message.strip().lower() == "quit":
            client_socket.close()
            break
        
        if not message.strip():
            print("Error: Message cannot be empty.")
            continue

        # Simulate error occurrence
        error_probability = 0.0
        message_with_error = simulate_error(message, error_probability)

        checksum = calculate_checksum(message_with_error)
        data_to_send = f"{message_with_error}{checksum:05}"
        client_socket.send(data_to_send.encode())

if __name__ == "__main__":
    IP = "127.0.0.1"  # Change this to the server's IP if needed
    PORT = 12345      # Must match server's port
    start_client(IP, PORT)
