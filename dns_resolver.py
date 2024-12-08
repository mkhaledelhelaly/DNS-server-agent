import socket

# Resolver details
resolver_ip = '127.0.0.1'
resolver_port = 53
root_ip = '127.0.0.1'
root_port = 5353
tld_ip = '127.0.0.1'
tld_port = 5354
auth_ip = '127.0.0.1'
auth_port = 5355

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((resolver_ip, resolver_port))

while True:
    # Step 1: Receive data from the client
    data, addr = sock.recvfrom(512)
    print(f"Resolver received data from client: {data}")

    # Step 2: Send data to the root server
    sock.sendto(data, (root_ip, root_port))
    print(f"Resolver sent data to root server")

    # Step 3: Receive response from the root server
    root_response, _ = sock.recvfrom(512)
    print(f"Resolver received response from root: {root_response}")

    # Step 4: Send response to the TLD server
    sock.sendto(root_response, (tld_ip, tld_port))
    print(f"Resolver sent data to TLD server")

    # Step 5: Receive response from the TLD server
    tld_response, _ = sock.recvfrom(512)
    print(f"Resolver received response from TLD: {tld_response}")

    # Step 6: Send response to the authoritative server
    sock.sendto(tld_response, (auth_ip, auth_port))
    print(f"Resolver sent data to authoritative server")

    # Step 7: Receive response from the authoritative server
    auth_response, _ = sock.recvfrom(512)
    print(f"Resolver received response from authoritative: {auth_response}")

    # Step 8: Send the final response to the client
    sock.sendto(auth_response, addr)
    print(f"Resolver sent data back to client")