import socket

root_ip = '127.0.0.1'
root_port = 5354

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((root_ip, root_port))

# Root server database with NS records for TLDs .com and .org
root_database = {
    "com": {"NS": [{"value": b"ns1.tld-com.server", "ttl": 3600}]},
    "org": {"NS": [{"value": b"ns1.tld-org.server", "ttl": 3600}]}
}

def get_root(binary_domain_name):
    idx = 0
    last_label = b''

    while binary_domain_name[idx] != 0:  # Iterate until the null byte
        label_length = binary_domain_name[idx]  # Get the length of the current label
        last_label = binary_domain_name[idx:idx + label_length + 1]  # Extract the current label
        idx += label_length + 1  # Move to the next label

    return last_label  # Return the last label

def decode_label(binary_label):
    """
    Decodes the binary label into a human-readable string.
    Ignores the first byte (length byte) and converts the rest to a string.
    """
    length = binary_label[0]  # First byte is the length of the label
    label_bytes = binary_label[1:]  # Exclude the length byte
    label = label_bytes.decode('utf-8', errors='ignore')  # Decode the label to string (ignoring invalid bytes)
    return label

def encode_domain_name(domain):
    """
    Encodes a domain name into the binary format used in DNS.
    """
    labels = domain.split('.')
    encoded = b""
    for label in labels:
        encoded += len(label).to_bytes(1, byteorder='big') + label.encode('utf-8')
    encoded += b'\0'  # Null byte at the end
    return encoded

def send_ns_records(tld, addr):
    """
    Given a TLD, return the NS records for that TLD from the root server database and send a response in binary format.
    """
    if tld in root_database:
        ns_records = root_database[tld]["NS"]
        response = b''

        # Each NS record consists of the domain name (encoded), type (NS), class (IN), TTL, and RDATA (nameserver).
        for record in ns_records:
            # Name (TLD)
            tld_name = encode_domain_name(tld)
            # Type (NS) - Type 2
            type_ns = (2).to_bytes(2, byteorder='big')  # NS record type (2 bytes)
            # Class (IN) - Class 1
            class_in = (1).to_bytes(2, byteorder='big')  # IN class (2 bytes)
            # TTL (Time to Live)
            ttl = record["ttl"].to_bytes(4, byteorder='big')  # TTL as 4-byte integer
            # RDATA (nameserver)
            ns_name = encode_domain_name(record['value'].decode())

            # Combine all parts to form the NS record in binary
            response += tld_name + type_ns + class_in + ttl + len(ns_name).to_bytes(2, byteorder='big') + ns_name

        # Send the response to the DNS resolver
        sock.sendto(response, addr)
        print(f"Root Server sent NS records for {tld}: {response}")
    else:
        # If the TLD is not found, return a failure message
        error_message = b"Error: TLD not found"
        sock.sendto(error_message, addr)
        print(f"Root Server sent error message: {error_message}")


while True:
    # Step 1: Receive the query from the resolver
    binary_domain_name, addr = sock.recvfrom(512)
    print(f"Root Server received domain name: {binary_domain_name}")

    # Step 2: Get the last label (TLD) from the binary domain name
    root_label = get_root(binary_domain_name)
    print(f"Root Label = {root_label}")

    # Step 3: Decode the root label to a human-readable string
    decoded_root_label = decode_label(root_label)
    print(f"Decoded Root Label = {decoded_root_label}")

    # Step 4: Get the NS records for the TLD (root label) and send the response in binary
    send_ns_records(decoded_root_label, addr)
