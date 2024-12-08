import socket

root_ip = '127.0.0.1'
root_port = 5353

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((root_ip, root_port))

while True:
    data, addr = sock.recvfrom(512)
    print(f"Root Server received data: {data}")

    # Responding to the resolver
    response = b"Root Response"
    sock.sendto(response, addr)
    print(f"Root Server sent response")