import socket

tld_ip = '127.0.0.1'
tld_port = 5354

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((tld_ip, tld_port))

while True:
    data, addr = sock.recvfrom(512)
    print(f"TLD Server received data: {data}")

    # Responding to the resolver
    response = b"TLD Response"
    sock.sendto(response, addr)
    print(f"TLD Server sent response")

