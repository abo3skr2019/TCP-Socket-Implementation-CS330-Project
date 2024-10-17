import socket
import threading
import random

# Function to calculate checksum
def calculate_checksum(message):
    checksum = sum(bytearray(message, 'utf-8')) % 65536
    return ~checksum & 0xFFFF  # 16-bit one's complement

# Function to handle client connections
def handle_client(client_socket):
    while True:
        received_data = client_socket.recv(1024).decode('utf-8')
        if not received_data:
            break
        
        # Extracting message and checksum
        message, received_checksum = received_data[:-5], int(received_data[-5:])
        calculated_checksum = calculate_checksum(message)
        
        # Check checksum
        if calculated_checksum != received_checksum:
            client_socket.send("Error: The Received Message is not correct.".encode())
        else:
            print(f"Client says: {message}")
            confirmation_message = "Message received correctly"
            client_socket.send(f"{confirmation_message}{calculate_checksum(confirmation_message):05}".encode())
    
    client_socket.close()

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"Server listening on port {port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

def send_messages(server_socket):
    while True:
        message = input("Enter message to send (type 'Quit' to exit): ")
        if message.strip().lower() == "quit":
            server_socket.close()
            break
        if not message.strip():
            print("Error: Message cannot be empty.")
            continue
        
        checksum = calculate_checksum(message)
        data_to_send = f"{message}{checksum:05}"
        server_socket.send(data_to_send.encode())

if __name__ == "__main__":
    PORT = 12345  # Change this port as needed
    threading.Thread(target=start_server, args=(PORT,)).start()
    send_messages(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
