import socket

# TLD server details
tld_ip = '127.0.0.1'
tld_port = 5355

# Initialize the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((tld_ip, tld_port))

# TLD database
# The database contains NS records for domains under this TLD
tld_database = {
    "example.com": {
        "NS": [
            {"value": b"ns1.auth-example.com", "ttl": 3600},
        ]
    },
    "example.org": {
        "NS": [
            {"value": b"ns1.auth-example.org", "ttl": 3600},
        ]
    },
}

# Reuse shared helper functions from the root server
def get_records(domain):
    if domain in tld_database:
        # Retrieve NS records for the given domain
        ns_records = tld_database[domain]["NS"]
        
        records = []
        
        for record in ns_records:
            # Each record is a dictionary with a 'value' (nameserver) and 'ttl' (time to live)
            record_data = {
                "name": domain.encode(),  # The domain itself
                "type": 2,  # NS record type is 2
                "class": 1,  # IN class is 1
                "ttl": record["ttl"],  # TTL in seconds
                "rdata": record["value"],  # RDATA is the nameserver value
            }
            records.append(record_data)
        
        return records
    else:
        # If the domain is not found, return an empty list
        return []

def build_response(data):
    # Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)
    records = get_records(domain_name)

    # Transaction ID (from the original query)
    transaction_id = data[:2]

    # Determine Rcode (return 3 for NXDOMAIN if no records are found)
    Rcode = f"{3 if not records else 0:04b}"

    # Flags (standard query response)
    flags = get_flags(Rcode)

    # Question Count (1 question)
    qdcount = b'\x00\x01'

    # Answer Count (how many answers are being returned)
    anscount = len(records).to_bytes(2, byteorder='big')

    # No additional authority or additional records
    authcount = b'\x00\x00'
    addcount = b'\x00\x00'

    # DNS header (Transaction ID, Flags, Question Count, Answer Count, Authority Count, Additional Count)
    dns_header = transaction_id + flags + qdcount + anscount + authcount + addcount

    # DNS question section (domain name and query type)
    question_section = data[12:]  # Echo the question from the request

    # DNS body (resource records)
    answer_section = convert_records_to_binary(records)

    return dns_header + question_section + answer_section


while True:
    # Step 1: Receive the query from the resolver
    data, addr = sock.recvfrom(512)
    print(f"TLD received data from Resolver: {data}")

    # Step 2: Build the response
    response = build_response(data)

    # Step 3: Send the response back to the resolver
    sock.sendto(response, addr)
    print(f"TLD sent Response {response} to Resolver")
