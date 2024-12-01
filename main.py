import socket
from functions import *

port = 53
IP = '127.0.0.1'

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP, port))

# Main loop to receive and respond to DNS queries
try:
    while True:
        # Receive the DNS query (max 512 bytes)
        data, addr = sock.recvfrom(512)
        print(f"Received query from {addr}")

        # Build the response based on the query
        response = build_response(data)

        # Send the response back to the client
        sock.sendto(response, addr)
        print(f"Sent response to {addr}")
        
except KeyboardInterrupt:
    print('Shutting down DNS server')
    sock.close()