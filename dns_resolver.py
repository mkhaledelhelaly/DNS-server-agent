import socket
import threading

# Resolver details
resolver_ip = '127.0.0.1'
resolver_port = 53
root_ip = '127.0.0.1'
root_port = 5354
tld_ip = '127.0.0.1'
tld_port = 5356
auth_ip = '127.0.0.1'
auth_port = 5357

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((resolver_ip, resolver_port))

#Lock for thread synchronization
lock = threading.Lock()

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

##################################################################################################################################################
def remove_ns_records_and_reset_qr(response):

    # Extract the header and modify the QR bit
    header = bytearray(response[:12])  # First 12 bytes are the header
    header[2] &= 0x7F  # Clear the QR bit (set it to 0)

    # Parse counts from the header
    qdcount = int.from_bytes(header[4:6], byteorder='big')  # Number of questions
    ancount = int.from_bytes(header[6:8], byteorder='big')  # Number of answers
    nscount = int.from_bytes(header[8:10], byteorder='big')  # Number of authority records
    arcount = int.from_bytes(header[10:12], byteorder='big')  # Number of additional records

    # Locate the question section
    offset = 12
    for _ in range(qdcount):
        while response[offset] != 0:  # Domain name ends with a null byte (0)
            offset += response[offset] + 1
        offset += 5  # Null byte + QTYPE (2 bytes) + QCLASS (2 bytes)

    # Skip the answer section
    for _ in range(ancount):
        while response[offset] != 0:  # Domain name ends with a null byte (0)
            offset += response[offset] + 1
        offset += 10  # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        rdlength = int.from_bytes(response[offset - 2:offset], byteorder='big')
        offset += rdlength  # Skip RDATA

    # The authority section starts at the current offset
    authority_start = offset

    # Skip the authority section
    for _ in range(nscount):
        while response[offset] != 0:  # Domain name ends with a null byte (0)
            offset += response[offset] + 1
        offset += 10  # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        rdlength = int.from_bytes(response[offset - 2:offset], byteorder='big')
        offset += rdlength  # Skip RDATA

    # Rebuild the response with an empty authority section
    header[8:10] = b'\x00\x00'  # Set nscount to 0
    modified_response = bytes(header) + response[12:authority_start] + response[offset:]

    return modified_response

#################################################################################################################################
def check_for_error(response):
    # Flags are in bytes 2 and 3 of the response
    flags = response[2:4]
    
    # Convert the flags to a 16-bit integer
    flags_int = int.from_bytes(flags, byteorder='big')
    
    # Extract the last 4 bits (Rcode)
    rcode = flags_int & 0b1111  # Mask the last 4 bits

    if rcode == 0:
        print("No error found in Query")
    elif rcode == 1:
        print("RCODE = 1: Format Error in Query sent to server")
    elif rcode == 3:
        print("RCODE = 3: Non-Existent Domain")
    elif rcode ==4:
        print("RCODE = 4: Unsupported Query Type")

    return response

################################################################################################################################
def handle_query(data, addr):

    thread_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   
    try:
        binary_domain_name = get_binary_domain(data)
        if b'\x04arpa\x00' in binary_domain_name:
            return  # Reject reverse lookup for ARPA domains

        print(f"Binary Domain Name = {binary_domain_name}")
        print(f"Resolver received data from client: {data}")
        
        # ROOT SERVER
        # with lock:
        print("\n\nROOT SERVER:")
        sock.sendto(data, (root_ip, root_port))
        print(f"Resolver sent data {data} to root server")
        root_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from root: {root_response}")
        root_response = check_for_error(root_response)
        
        # TLD SERVER
        # with lock:
        print("\n\nTLD SERVER:")
        tld_query = remove_ns_records_and_reset_qr(root_response)  # We are using constant IPs
        print(f"TLD Query: {tld_query}")
        sock.sendto(tld_query, (tld_ip, tld_port))
        print(f"Resolver sent data to TLD server: {root_response}")
        tld_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from TLD: {tld_response}")
        tld_response = check_for_error(tld_response)
        
        # AUTHORITATIVE SERVER
        #with lock:
        print("\n\nAUHORITATIVE SERVER:")
        auth_query = remove_ns_records_and_reset_qr(tld_response)
        print(f"Authoritative Query: {auth_query}")
        sock.sendto(auth_query, (auth_ip, auth_port))
        print(f"Resolver sent data {auth_query} to authoritative server")
        auth_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from authoritative: {auth_response}")
        auth_response = check_for_error(auth_response)

        # Send the final response to the client
        sock.sendto(auth_response, addr)
        print(f"Resolver sent data back to client \n\n\n\n")

    finally:
        thread_sock.close() 


while True:
        # Step 1: Receive data from the client
        data, addr = sock.recvfrom(512)
        handle_query(data, addr)

        # # Create a new thread for each incoming request
        # threading.Thread(target=handle_query, args=(data, addr)).start()
    

