import sys
import socket
import json
import threading
import time

HOST_PORT_START = 5000  # Starting port number for hosts

def communicate_with_other_hosts(hostname, ip_address, port, config_data):
    """This function will handle both listening and communicating with other hosts."""
    # Create a server socket to listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)
    server_socket.bind((ip_address, port))
    server_socket.listen(len(config_data))  # Number of hosts in the network
    print(f"Host {hostname} listening on {ip_address}:{port}.")

    # Function to accept connections and receive messages
    def accept_connections():
        while True:
            conn, addr = server_socket.accept()
            data = conn.recv(1024).decode()
            print(f"{hostname} received from {addr}: {data}")
            conn.close()

    # Start a thread to handle incoming connections
    threading.Thread(target=accept_connections, daemon=True).start()

    # Periodically send messages to all other hosts
    def send_messages():
        while True:
            for other_hostname, other_ip in config_data.items():
                if other_hostname != hostname:  # Don't connect to self
                    other_port = HOST_PORT_START + int(other_hostname[-2:])
                    try:
                        # Create a client socket to send a message to the other host
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)
                        client_socket.connect((other_ip, other_port))
                        message = f"Hello from {hostname} to {other_hostname}"
                        client_socket.send(message.encode())
                        client_socket.close()
                        print(f"Sent message from {hostname} to {other_hostname} at {other_ip}:{other_port}")
                    except ConnectionRefusedError:
                        print(f"Failed to connect to {other_hostname} at {other_ip}:{other_port}")
            # Sleep for a few seconds before sending the next round of messages
            time.sleep(5)  # Adjust the sleep time as needed

    # Start a thread to send messages periodically
    threading.Thread(target=send_messages, daemon=True).start()

    # Instead of input() to keep the script running, use a while loop
    try:
        while True:
            time.sleep(1)  # Sleep to prevent the loop from consuming excessive CPU
    except KeyboardInterrupt:
        print(f"{hostname} interrupted, stopping.")
        server_socket.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <hostname>")
        sys.exit(1)

    hostname = sys.argv[1]

    # Load the configuration from the JSON file
    with open('config.json', 'r') as config_file:
        config_data = json.load(config_file)

    # Get the IP address and port for the current host
    ip_address = config_data.get(hostname)
    if not ip_address:
        print(f"Hostname {hostname} not found in config.")
        sys.exit(1)
    
    # Derive port number based on the hostname
    port = HOST_PORT_START + int(hostname[-2:])

    # Start communication with other hosts
    communicate_with_other_hosts(hostname, ip_address, port, config_data)

if __name__ == "__main__":
    main()
