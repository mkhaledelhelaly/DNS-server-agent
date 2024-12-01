import socket

# Example of malformed queries
malformed_queries = [
    b'\x12\x34',  # Too short
    b'\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90'  # Incorrect format
]

# Send each malformed query to the DNS server
for query in malformed_queries:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ('127.0.0.1', 53))
    try:
        response, _ = sock.recvfrom(512)
        print(f"Response: {response}")
    except socket.timeout:
        print("No response received for malformed query")
