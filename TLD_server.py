import socket
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# DNS database for TLD server (storing NS records for domains)
dns_database = {
    "example.com": {
        "A": [
            {"value": "192.0.2.1", "ttl": 3600}
        ],
        "MX": [
            {"value": "10 mail.example.com", "ttl": 3600}
        ],
        "NS": [
            {"value": "ns1.example.com", "ttl": 3600},
            {"value": "ns2.example.com", "ttl": 3600}
        ]
    }
}



# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 1053))

def parse_query(data):
    domain_parts = []
    idx = 12

    while data[idx] != 0:
        length = data[idx]
        domain_parts.append(data[idx + 1: idx + 1 + length].decode())
        idx += length + 1

    domain_name = ".".join(domain_parts)
    query_type = int.from_bytes(data[idx + 1: idx + 3], "big")

    return domain_name, query_type

def fetch_records(domain_name, query_type):
    query_type_map = {1: "A", 5: "CNAME", 15: "MX", 2: "NS"}
    record_type = query_type_map.get(query_type, None)

    # If query is for NS records, check the TLD DNS database
    if record_type and domain_name in dns_database and record_type in dns_database[domain_name]:
        return dns_database[domain_name][record_type]
    return []

def build_response(transaction_id, domain_name, query_type, records):
    flags = b'\x85\x80'  # Standard response, no error, with AA flag
    qdcount = b'\x00\x01'
    ancount = len(records).to_bytes(2, "big")
    authcount = b'\x00\x00'
    addcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + ancount + authcount + addcount

    question = b''
    for label in domain_name.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00' + query_type.to_bytes(2, "big") + b'\x00\x01'

    answer = b''
    for record in records:
        answer += b'\xc0\x0c'  # Pointer to domain name
        if query_type == 1:  # A record
            answer += b'\x00\x01\x00\x01'
            answer += int(record["ttl"]).to_bytes(4, "big")
            answer += b'\x00\x04'
            answer += bytes(map(int, record["value"].split('.')))
        elif query_type == 2:  # NS record
            answer += b'\x00\x02\x00\x01'
            answer += int(record["ttl"]).to_bytes(4, "big")
            ns_parts = record["value"].split('.')
            ns_data = b''
            for part in ns_parts:
                ns_data += bytes([len(part)]) + part.encode()
            ns_data += b'\x00'
            answer += len(ns_data).to_bytes(2, "big") + ns_data

    return header + question + answer

def handle_request(data, addr):
    transaction_id = data[:2]
    domain_name, query_type = parse_query(data)
    logging.info(f"Received query for {domain_name} of type {query_type}")
    records = fetch_records(domain_name, query_type)

    if records:
        response = build_response(transaction_id, domain_name, query_type, records)
        logging.info(f"Sending response for {domain_name}")
    else:
        logging.warning(f"No records found for {domain_name}")
        response = transaction_id + b'\x81\x83' + b'\x00\x01\x00\x00\x00\x00\x00\x00'  # NXDOMAIN

    sock.sendto(response, addr)

try:
    logging.info("TLD DNS Server is running...")
    while True:
        data, addr = sock.recvfrom(512)
        handle_request(data, addr)
except KeyboardInterrupt:
    logging.info("Shutting down TLD DNS Server...")
    sock.close()
