import socket
import logging
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define the DNS database
dns_database = {
    "example.com": {
        "A": [
            {"value": "127.0.0.1", "ttl": 3600}
        ],
        "CNAME": [
            {"value": "www.example.com", "ttl": 3600}
        ],
        "MX": [
            {"value": "mail.example.com", "ttl": 3600, "priority": 10}  # Added priority
        ]
    },
    "anotherdomain.com": {
        "A": [
            {"value": "192.168.1.1", "ttl": 3600}
        ],
        "NS": [
            {"value": "ns1.anotherdomain.com", "ttl": 3600}
        ],
        "MX": [
            {"value": "mail.anotherdomain.com", "ttl": 3600, "priority": 20}  # Added priority
        ]
    },
    "google.com": {
        "A": [
            {"value": "142.250.190.78", "ttl": 300}
        ],
        "CNAME": [
            {"value": "www.google.com", "ttl": 300}
        ],
        "MX": [
            {"value": "alt1.google.com", "ttl": 300, "priority": 10},  # Added priority
            {"value": "alt2.google.com", "ttl": 300, "priority": 20}  # Added another MX with different priority
        ]
    },
    "wikipedia.org": {
        "A": [
            {"value": "208.80.154.224", "ttl": 300}
        ],
        "NS": [
            {"value": "ns1.wikipedia.org", "ttl": 300}
        ],
        "MX": [
            {"value": "mail.wikipedia.org", "ttl": 300, "priority": 5}  # Added priority
        ]
    }
}


dns_cache = {}


# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 53))


# Retrieve records (with cache support)
def get_records(domain_name, query_type):
    """Retrieve DNS records, either from cache or from the database."""
    cached_records = get_from_cache(domain_name, query_type)
    if cached_records:
        print("found in cache")
        return cached_records

    if domain_name in dns_database and query_type in dns_database[domain_name]:
        records = dns_database[domain_name][query_type]
        ttl = records[0]['ttl']  # Assuming all records have the same TTL
        add_to_cache(domain_name, records, ttl)
        print("not found in cache")
        return records
    return []


def add_to_cache(domain_name, records, ttl):
    """Store DNS records in the cache with an expiration time."""
    expiration_time = time.time() + ttl  # TTL is in seconds
    dns_cache[domain_name] = (records, expiration_time)


# Function to get records from the cache
def get_from_cache(domain_name, query_type):
    """Check the cache for the requested DNS record."""
    current_time = time.time()
    if domain_name in dns_cache:
        cached_records, expiration_time = dns_cache[domain_name]
        if current_time < expiration_time:
            return [record for record in cached_records if record['type'] == query_type]
        else:
            del dns_cache[domain_name]  # Remove expired entry
    return None


# Function to extract flags
def get_flags(Rcode):
    QR = '1'
    opcode = '0000'
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    # Rcode = f"{get_rcode(domainname, query_type):04b}"
    print(f"Rcode (binary) = {Rcode}")

    # Concatenate all the parts into a single binary string
    flags = QR + opcode + AA + TC + RD + RA + Z + str(Rcode)

    # Convert the binary string to an integer, then to bytes
    flags = int(flags, 2).to_bytes(2, byteorder='big')
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

    idx = 12  # index starts at 12 because the first 12 bytes are reserved for the header

    while data[idx] != 0:  # Domain name ends with a null byte (0)
        length = data[idx]  # The first byte at the current idx indicates the length of the next segment (label) of the domain name.

        start = idx + 1
        end = idx + 1 + length
        label_bytes = data[start:end]
        label = label_bytes.decode()  # coverts from bytes to string
        domain_parts.append(label)

        idx += length + 1

    domain_name = ".".join(domain_parts)  # joins labels using a dot
    query_type_value = int.from_bytes(data[idx + 1: idx + 3],byteorder='big')  # 2 bytes after domain name represent query type (A, CName, MX, ....)

    query_type = query_type_map.get(query_type_value, 'UNKNOWN')

    return domain_name, query_type


def get_rcode(domain_name, query_type, data):
    if not validate_query(data):  # Malformed query
        return 1  # FORMERR
    if domain_name not in dns_database:  # Non-existent domain
        return 3  # NXDOMAIN
    if query_type not in ['A', 'CNAME', 'MX', 'NS']:  # Unsupported query type
        return 4  # NOTIMP
    
    # 2 -> server failure
    # 5 -> policy restricition
    return 0  # NOERROR


# Function to build the DNS response body (resource records)
def build_records(domain_name, record_type, records):
    response_body = b""

    for record in records:
        ttl = record['ttl']
        value = record['value']
        if record_type == 'A':
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x01'  # Specifies the record type as A (1)
            response_body += b'\x00\x01'  # Specifies Class IN (Internet)
            response_body += int(ttl).to_bytes(4,byteorder='big')  # Converts the Integer TTL value to a 4-byte binary representation
            response_body += b'\x00\x04'  # Length of the address (4 bytes for type A)

            ip_integers = map(int, value.split('.'))  # Split ip address to integers
            ip_bytes = bytes(ip_integers)  # convert ip address integers to bytes
            response_body += ip_bytes

        elif record_type == 'CNAME':
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x05'  # Specifies the record type as CNAME (5)
            response_body += b'\x00\x01'  # Specifies Class IN (Internet)
            response_body += int(ttl).to_bytes(4,
                                               byteorder='big')  # Converts the Integer TTL value to a 4-byte binary representation

            cname_labels = value.split('.')  # Split the CNAME target into labels
            cname_bytes = b""
            for label in cname_labels:
                label_length = len(label).to_bytes(1,
                                                   byteorder='big')  # Convert the length of the label to a single byte.
                label_encoded = label.encode()  # Encode the label (string) to bytes.
                cname_bytes += label_length + label_encoded
            cname_bytes += b'\x00'  # Add the null byte to terminate the CNAME

            response_body += len(cname_bytes).to_bytes(2, byteorder='big')  # Length of the CNAME record
            response_body += cname_bytes  # Append the CNAME record

        elif record_type == 'NS':
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x02'  # Specifies the record type as NS (2)
            response_body += b'\x00\x01'  # Specifies Class IN (Internet)
            response_body += int(ttl).to_bytes(4,
                                               byteorder='big')  # Converts the Integer TTL value to a 4-byte binary representation

            ns_labels = value.split('.')  # Split the NS target into labels
            ns_bytes = b""
            for label in ns_labels:
                label_length = len(label).to_bytes(1,
                                                   byteorder='big')  # Convert the length of the label to a single byte.
                label_encoded = label.encode()  # Encode the label (string) to bytes.
                ns_bytes += label_length + label_encoded
            ns_bytes += b'\x00'  # Add the null byte to terminate the NS name

            response_body += len(ns_bytes).to_bytes(2, byteorder='big')
            response_body += ns_bytes

        elif record_type == 'MX':
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x0f'  # Specifies the record type as MX (15)
            response_body += b'\x00\x01'  # Specifies Class IN (Internet)
            response_body += int(ttl).to_bytes(4,
                                               byteorder='big')  # Converts the Integer TTL value to a 4-byte binary representation

            priority = record['priority']
            response_body += (2 + len(value) + 2).to_bytes(2, byteorder='big')  # Length of the MX record
            response_body += priority.to_bytes(2, byteorder='big')  # Convert priority to 2 bytes

            mx_labels = value.split('.')  # Split the MX target into labels
            mx_bytes = b""
            for label in mx_labels:
                label_length = len(label).to_bytes(1,
                                                   byteorder='big')  # Convert the length of the label to a single byte.
                label_encoded = label.encode()  # Encode the label (string) to bytes.
                mx_bytes += label_length + label_encoded
            mx_bytes += b'\x00'  # Add the null byte to terminate the MX name

            response_body += mx_bytes

    return response_body


# Function to build the DNS response
def build_response(data):
    # Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)
    # Retrieve the records from the database
    records = get_records(domain_name, query_type)



    # Transaction ID (from the original query)
    transaction_id = data[:2]


    Rcode = f"{get_rcode(domain_name, query_type, data):04b}"
    # Flags (standard query response)
    flags = get_flags(Rcode)
    print(f"Flags: {flags}\n")


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
    question_section = data[12:]  # The Question Section in a response is an echo of the question from the request.

    # DNS body (resource records)
    answer_section = build_records(domain_name, query_type, records)

    return dns_header + question_section + answer_section


# Validate and sanitize incoming DNS queries
def validate_query(data):
    # Ensure the query is not too short
    if len(data) < 12:
        logging.warning("Query too short, possible attack detected.")
        return False
    
    # Ensure the query is a standard query (QR = 0)
    if data[2] & 0x80 != 0:
        logging.warning("Query is a response, not a request.")
        return False
    
    num_questions = (data[4] << 8) | data[5]
    if num_questions != 1:
        logging.warning(f"Unexpected number of questions: {num_questions}")
        return False
    
    return True


def handle_request(data, addr):
    logging.info(f"Processing query from {addr}")
    response = build_response(data)
    print(f"DNS Response Message = {response}")
    #if rcode fel respone == 0 then send response, else hay'ba eh??? logging.warning w ne print rcode w ma3nah??
    sock.sendto(response, addr)
    logging.info(f"Sent response to {addr}")


try:
    while True:
        data, addr = sock.recvfrom(512)
        logging.info(f"Received query from {addr}")
        
        # Spawn a new thread for each request
        thread = threading.Thread(target=handle_request, args=(data, addr))
        thread.start()
except KeyboardInterrupt:
    logging.info('Shutting down DNS server...')
    sock.close()
