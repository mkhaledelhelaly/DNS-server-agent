import socket
import logging

# Resolver details
resolver_ip = '127.0.0.1'
resolver_port = 53
root_port = 5354
tld_port = 5356
auth_port = 5357

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((resolver_ip, resolver_port))

################################################################################################################

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


#################################################################################################################################
def extract_ip_from_response(response):
    # Skip the DNS header (12 bytes)
    pointer = 12

    # Skip the Question Section
    qdcount = int.from_bytes(response[4:6], byteorder="big")  # Number of questions
    for _ in range(qdcount):
        while response[pointer] != 0:  # Find the end of the domain name
            pointer += response[pointer] + 1
        pointer += 5  # Skip null byte, QTYPE (2 bytes), QCLASS (2 bytes)

    # Skip the Answer and Authority Sections
    ancount = int.from_bytes(response[6:8], byteorder="big")  # Number of answers
    nscount = int.from_bytes(response[8:10], byteorder="big")  # Number of NS records
    for _ in range(ancount + nscount):
        if response[pointer] & 0xC0 == 0xC0:  # Name compression pointer
            pointer += 2
        else:
            while response[pointer] != 0:  # Find the end of the domain name
                pointer += response[pointer] + 1
            pointer += 1  # Skip null byte
        pointer += 10  # Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        rdlength = int.from_bytes(response[pointer - 2:pointer], byteorder="big")
        pointer += rdlength

    # Parse the Additional Section
    arcount = int.from_bytes(response[10:12], byteorder="big")  # Number of additional records
    for _ in range(arcount):
        if response[pointer] & 0xC0 == 0xC0:  # Name compression pointer
            pointer += 2
        else:
            while response[pointer] != 0:  # Find the end of the domain name
                pointer += response[pointer] + 1
            pointer += 1  # Skip null byte

        record_type = int.from_bytes(response[pointer:pointer + 2], byteorder="big")
        pointer += 8  # Skip TYPE (2), CLASS (2), TTL (4)

        rdlength = int.from_bytes(response[pointer:pointer + 2], byteorder="big")
        pointer += 2  # Skip RDLENGTH

        if record_type == 1:  # A record (IPv4 address)
            ip_bytes = response[pointer:pointer + rdlength]
            ip_address = ".".join(map(str, ip_bytes))  # Convert bytes to dotted-decimal format
            return ip_address

        pointer += rdlength  # Skip RDATA for non-A records

    return None  # No A record found in Additional Section


#################################################################################################################################

def check_for_error(response):
    # Flags are in bytes 2 and 3 of the response
    flags = response[2:4]
    
    # Convert the flags to a 16-bit integer
    flags_int = int.from_bytes(flags, byteorder='big')
    
    # Extract the last 4 bits (Rcode)
    rcode = flags_int & 0b1111

    if rcode == 0:
        print("No error found in Query")
    elif rcode == 1:
        logging.warning("RCODE = 1: Format Error in Query sent to server")
    elif rcode == 2:
        logging.warning("RCODE = 2: Server Failure")    
    elif rcode == 3:
        logging.warning("RCODE = 3: Non-Existent Domain")
    elif rcode ==4:
        logging.warning("RCODE = 4: Unsupported Query Type")
    elif rcode == 5:
        logging.warning("RCODE = 5: Policy Restricion")

    return response

################################################################################################################################
def handle_query(data, addr):
    
        binary_domain_name = get_binary_domain(data)
        if b'\x04arpa\x00' in binary_domain_name:
                return  # Reject reverse lookup for ARPA domains for debugging

        print(f"Binary Domain Name = {binary_domain_name}")
        print(f"Resolver received data from client: {data}")

        # ROOT SERVER
        print("\n\nROOT SERVER:")
        root_ip = '127.0.0.1'
        sock.sendto(data, (root_ip, root_port))
        print(f"Resolver sent data {data} to root server")
        root_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from root: {root_response}")
        root_response = check_for_error(root_response)
        if root_response[3] & 0x0F != 0:  # If RCODE is non-zero
                logging.warning("Error detected in Root Server response. Stopping query.\n\n")
                sock.sendto(root_response, addr)  # Relay the error response to the client
                return

        # TLD SERVER
        print("\n\nTLD SERVER:")
        tld_query = data
        print(f"TLD Query: {tld_query}")
        tld_ip = extract_ip_from_response(root_response)
        print(f"TLD IP Address: {tld_ip}")
        sock.sendto(tld_query, (tld_ip, tld_port))
        print("Resolver sent data to TLD server: {tld_query}")
        tld_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from TLD: {tld_response}")
        tld_response = check_for_error(tld_response)
        if tld_response[3] & 0x0F != 0:  # If RCODE is non-zero
                logging.warning("Error detected in TLD Server response. Stopping query.\n\n")
                sock.sendto(tld_response, addr)  # Relay the error response to the client
                return

        # AUTHORITATIVE SERVER
        print("\n\nAUHORITATIVE SERVER:")
        auth_query = data
        print(f"Authoritative Query: {auth_query}")
        auth_ip = extract_ip_from_response(tld_response)
        print(f"AUTHORITATIVE IP Address: {auth_ip}")
        sock.sendto(auth_query, (root_ip, auth_port))
        print(f"Resolver sent data {auth_query} to authoritative server")
        auth_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from authoritative: {auth_response}")
        auth_response = check_for_error(auth_response)
        if auth_response[3] & 0x0F != 0:  # If RCODE is non-zero
                logging.warning("Error detected in Authoritative Server response. Stopping query.\n\n")
                sock.sendto(auth_response, addr)  # Relay the error response to the client
                return

        # Send the final response to the client
        sock.sendto(auth_response, addr)
        print(f"\n\nResolver sent data back to client \n\n\n\n")


while True:
        data, addr = sock.recvfrom(512)
        handle_query(data, addr)
        #threading.Thread(target=handle_query, args=(data, addr)).start()

