import socket

# Define the DNS database
dns_database = {
    "example.com": {
        "A": [
            {"value": "127.0.0.1", "ttl": 3600}
        ]
    },

    "anotherdomain.com": {
        "A": [
            {"value": "192.168.1.1", "ttl": 3600}
        ]
    },

    "google.com": {
    "A": [
        {"value": "142.250.190.78", "ttl": 300}
    ],
    "AAAA": [
        {"value": "2607:f8b0:4009:801::200e", "ttl": 300}
    ],
    "CNAME": [
        {"value": "www.google.com", "ttl": 300}
    ]
    },

    "wikipedia.org": {
        "A": [
            {"value": "208.80.154.224", "ttl": 300}
        ],
        "AAAA": [
            {"value": "2620:0:862:ed1a::1", "ttl": 300}
        ]
    }
}


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 53))  # Bind to DNS port

# Function to extract flags
def get_flags():
    QR = '1'
    opcode = '0000'
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    Rcode = '0000'

    # Concatenate all the parts into a single binary string
    flags= QR + opcode + AA + TC + RD + RA + Z + Rcode

    # Convert the binary string to an integer, then to bytes
    flags = int(flags, 2).to_bytes(2, byteorder='big')  # 0x8400
    return flags

# Function to parse the domain name from the DNS query
def get_question_domain(data):
    domain_parts = []
    query_type_map = {
        1: 'A',
        28: 'AAAA',
        5: 'CNAME',
        15: 'MX',
        2: 'NS',
        12: 'PTR',
        6: 'SOA',
        16: 'TXT',
        33: 'SRV',
        255: 'ANY'
    }

    idx = 12  #index starts at 12 because the first 12 bytes are reserved for the header

    while data[idx] != 0:              #Domain name ends with a null byte (0)
        length = data[idx]             #The first byte at the current idx indicates the length of the next segment (label) of the domain name.
        
        start = idx + 1
        end = idx + 1 + length
        label_bytes = data[start:end]
        label = label_bytes.decode() #coverts from bytes to string
        domain_parts.append(label)
        
        idx += length + 1

    domain_name = ".".join(domain_parts) #joins labels using a dot
    query_type_value = int.from_bytes(data[idx + 1: idx + 3], byteorder='big') #2 bytes after domain name represent query type (A, CName, MX, ....)
    
    query_type = query_type_map.get(query_type_value, 'UNKNOWN')

    return domain_name, query_type

# Function to retrieve DNS record from the database
def get_records(domain_name, record_type):
    if domain_name in dns_database and record_type in dns_database[domain_name]:
        return dns_database[domain_name][record_type]
    return []

# Function to build the DNS response body (resource records)
def build_records(domain_name, record_type, records):
    response_body = b""

    for record in records:
        ttl = record['ttl']
        value = record['value']
        if record_type == 'A':
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x01'  # Type A (host address)
            response_body += b'\x00\x01'  # Class IN (Internet)
            response_body += int(ttl).to_bytes(4, byteorder='big')  # TTL (time-to-live)
            response_body += b'\x00\x04'  # Length of the address (4 bytes)
            response_body += bytes(map(int, value.split('.')))  # The IP address as bytes
    return response_body

# Function to build the DNS response
def build_response(data):
    #Transaction ID (from the original query)
    transaction_id = data[:2]

    #Flags (standard query response)
    flags = get_flags()
    print(f"Flags: {flags}\n")

    #Question Count (1 question)
    qdcount = b'\x00\x01'

    #Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)

    #Retrieve the records from the database
    records = get_records(domain_name, query_type)

    #Answer Count (how many answers are being returned)
    anscount = len(records).to_bytes(2, byteorder='big')

    #No additional authority or additional records
    authcount = b'\x00\x00'
    addcount = b'\x00\x00'

    # DNS header (Transaction ID, Flags, Question Count, Answer Count, Authority Count, Additional Count)
    dns_header = transaction_id + flags + qdcount + anscount + authcount + addcount

    # DNS question section (domain name and query type)
    question_section = data[12:]  #The Question Section in a response is an echo of the question from the request.

    # DNS body (resource records)
    answer_section = build_records(domain_name, query_type, records)

    return dns_header + question_section + answer_section

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
    print('Shutting down DNS server...')
    sock.close()
