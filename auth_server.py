import socket

auth_ip = '127.0.0.1'
auth_port = 5355

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((auth_ip, auth_port))

while True:
    data, addr = sock.recvfrom(512)
    print(f"Authoritative Server received data: {data}")

    # Responding to the resolver
    response = b"Authoritative Response"
    sock.sendto(response, addr)
    print(f"Authoritative Server sent response")