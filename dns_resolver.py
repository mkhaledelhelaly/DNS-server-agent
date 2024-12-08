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

################################################################################################################
# Function to parse the domain name from the DNS query
def get_binary_domain(data):
    """
    Extracts the domain name in its binary format directly from the DNS query data.
    """
    idx = 12  # Start after the 12-byte DNS header
    domain_bytes = bytearray()  # Initialize a bytearray to store the domain name

    while data[idx] != 0:  # Loop until the null byte indicating the end of the domain name
        label_length = data[idx]  # Get the length of the current label
        label = data[idx:idx + label_length + 1]  # Extract the label with its length byte
        domain_bytes.extend(label)  # Append the label to the binary domain name
        idx += label_length + 1  # Move to the next label

    domain_bytes.append(0)  # Add the final null byte to terminate the domain name
    return bytes(domain_bytes)  # Convert to immutable bytes and return

##################################################################################################################################################
while True:
    # Step 1: Receive data from the client
    data, addr = sock.recvfrom(512)
    print(f"Resolver received data from client: {data}")
    binary_domain_name= get_binary_domain(data)
    if b'\x04arpa\x00' in binary_domain_name:
        #print(f"Rejected domain name: {binary_domain_name}")
        continue

    print(f"Binary domain name = {binary_domain_name}")

    # Step 2: Send data to the root server
    sock.sendto(binary_domain_name, (root_ip, root_port))
    print(f"Resolver sent domain name {binary_domain_name} to root server")

    # Step 3: Receive response from the root server
    root_response, _ = sock.recvfrom(512)
    print(f"Resolver received response from root: {root_response}")

    # # Step 4: Send response to the TLD server
    # sock.sendto(root_response, (tld_ip, tld_port))
    # print(f"Resolver sent data to TLD server")

    # # Step 5: Receive response from the TLD server
    # tld_response, _ = sock.recvfrom(512)
    # print(f"Resolver received response from TLD: {tld_response}")

    # # Step 6: Send response to the authoritative server
    # sock.sendto(tld_response, (auth_ip, auth_port))
    # print(f"Resolver sent data to authoritative server")

    # # Step 7: Receive response from the authoritative server
    # auth_response, _ = sock.recvfrom(512)
    # print(f"Resolver received response from authoritative: {auth_response}")

    # # Step 8: Send the final response to the client
    # sock.sendto(auth_response, addr)
    # print(f"Resolver sent data back to client")