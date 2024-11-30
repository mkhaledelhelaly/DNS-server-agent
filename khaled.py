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
    }
}

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 53))  # Bind to DNS port

# Function to extract flags
def get_flags():
    # QR=1 (response), opcode=0000 (standard query), AA=1 (authoritative answer), RD=0 (recursion desired)
    flags = int('1000010000000000', 2).to_bytes(2, byteorder='big')  # 0x8180
    return flags

# Function to parse the domain name from the DNS query
def get_question_domain(data):
    domain_parts = []
    idx = 12  # Starting after the transaction ID, flags, and question count

    while data[idx] != 0:
        length = data[idx]
        domain_parts.append(data[idx + 1: idx + 1 + length].decode())
        idx += length + 1

    return ".".join(domain_parts), data[idx + 1: idx + 3]

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
    # Transaction ID (from the original query)
    transaction_id = data[:2]

    # Flags (standard query response)
    flags = get_flags()

    # Question Count (1 question)
    qdcount = b'\x00\x01'

    # Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)

    # Retrieve the records from the database (default to "A" type)
    records = get_records(domain_name, "A")  # Currently only handling "A" type records

    # Answer Count (how many answers are being returned)
    ancount = len(records).to_bytes(2, byteorder='big')

    # No additional authority or additional records
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'

    # DNS header (Transaction ID, Flags, Question Count, Answer Count, Authority Count, Additional Count)
    dns_header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # DNS question section (domain name and query type)
    question_section = data[12:]  # We keep the original question part intact

    # DNS body (resource records)
    answer_section = build_records(domain_name, "A", records)

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
