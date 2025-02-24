import socket
import logging
import threading

# TLD server details
tld_ip = '127.0.0.1'
tld_port = 5356

# Initialize the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((tld_ip, tld_port))

# TLD database
# The database contains NS records for domains under this TLD
tld_database = {
    "example.com": {
        "NS": [
            {"value": b"ns1.auth-example.com", "ttl": 3600},
        ],
        "A": [
            {"name": "ns1.auth-example.com", "value": "127.0.0.1", "ttl": 3600},
        ]
    },
    "example.org": {
        "NS": [
            {"value": b"ns1.auth-example.org", "ttl": 3600},
        ],
        "A": [
            {"name": "ns1.auth-example.org", "value": "127.0.0.1", "ttl": 3600},
        ]
    },
    "example.net": {
        "NS": [
            {"value": b"ns1.auth-example.net", "ttl": 3600},
        ],
        "A": [
            {"name": "ns1.auth-example.net", "value": "127.0.0.1", "ttl": 3600},
        ]
    }
}




######################################################################################################################

def encode_domain_name(domain):
    """
    Encodes a domain name into its binary format as per DNS specifications.
    """
    labels = domain.split('.')
    encoded = b""
    for label in labels:
        # The first byte is the length of the label
        encoded += len(label).to_bytes(1, byteorder='big') + label.encode('utf-8')
    encoded += b'\0'  # Null byte to terminate the domain name
    return encoded
######################################################################################################################
def convert_records_to_binary(records):
    # Initialize an empty bytearray to hold the concatenated binary records
    binary_records = bytearray()

    for record in records:
        # Encode the domain name (name of the TLD)
        encoded_name = encode_domain_name(record["name"].decode())

        # Type (2 bytes)
        encoded_type = record["type"].to_bytes(2, byteorder='big')

        # Class (2 bytes)
        encoded_class = record["class"].to_bytes(2, byteorder='big')

        # TTL (4 bytes)
        encoded_ttl = record["ttl"].to_bytes(4, byteorder='big')

        # RDATA (the nameserver value)
        encoded_rdata = encode_domain_name(record["rdata"].decode())

        # Length of the RDATA (2 bytes)
        encoded_rdata_length = len(encoded_rdata).to_bytes(2, byteorder='big')

        # Combine all parts of the record into a binary format
        binary_record = encoded_name + encoded_type + encoded_class + encoded_ttl + encoded_rdata_length + encoded_rdata

        # Append the binary record to the bytearray
        binary_records.extend(binary_record)

    return bytes(binary_records)  # Return the concatenated binary string
#################################################################################################################################

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

##############################################################################################################################################

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
    255: 'ANY',
    257: 'CAA',
    8: 'MG',
    9: 'MR', 
    13: 'HINFO',  
    7: 'MAILB', 
    14: 'MINFO',  
    10: 'NULL' 
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
##############################################################################################################
def get_additional_section(domain_name):

    additional_section = b""

    if domain_name in tld_database and "A" in tld_database[domain_name]:
        a_records = tld_database[domain_name]["A"]  # Fetch A records

        for record in a_records:
            ip_bytes = socket.inet_aton(record["value"])  # Convert IP to binary
            additional_section += (
                encode_domain_name(record["name"])  # Encode the domain name
                + b'\x00\x01'  # Type: A
                + b'\x00\x01'  # Class: IN
                + record["ttl"].to_bytes(4, byteorder="big")  # TTL
                + b'\x00\x04'  # RDLENGTH: 4 bytes for IPv4
                + ip_bytes  # RDATA: IP address in binary
            )
    return additional_section

############################################################################################################

def get_flags(Rcode):
    QR = '1'
    opcode = '0000'
    AA = '0'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    

    # Concatenate all the parts into a single binary string
    flags = QR + opcode + AA + TC + RD + RA + Z + str(Rcode)

    # Convert the binary string to an integer, then to bytes
    flags = int(flags, 2).to_bytes(2, byteorder='big')
    return flags


######################################################################################################################
def get_rcode(domain_name, query_type, data):
    if not validate_query_format(data):
        return 1  # FORMERR
    if query_type not in ['A', 'CNAME', 'MX', 'NS', 'AAAA', 'PTR', 'TXT', 'SOA', 'SRV', 'CAA', 'MG', 'MR', 'HINFO', 'MAILB', 'MINFO', 'NULL']:
        return 4  # NOTIMP
    if not get_records(domain_name):
        return 3  # NXDOMAIN
    return 0  # NOERROR

    # 2 -> server failure
    # 5 -> policy restriction

#######################################################################################################################

def validate_query_format(data):
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
#####################################################################################################################

def build_error_response(data, rcode):
    transaction_id = data[:2]  # Echo Transaction ID
    flags = get_flags(rcode)
    qdcount = b'\x00\x01'  # 1 question
    anscount = b'\x00\x00'
    authcount = b'\x00\x00'
    addcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + anscount + authcount + addcount
    question = data[12:]  # Echo the question section
    return header + question

####################################################################################################################

def build_response(data):
    # Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)
    print(f"Domain Name = {domain_name}")
    records = get_records(domain_name)
    print(f"NS records = {records}")

    # Transaction ID (from the original query)
    transaction_id = data[:2]


    Rcode = f"{get_rcode(domain_name, query_type, data):04b}"
    # Flags (standard query response)
    flags = get_flags(Rcode)
    

    if Rcode == '0000':
        # DNS question section (domain name and query type)
        question_section = data[12:]  # The Question Section in a response is an echo of the question from the request.
        
        # DNS body (resource records)
        authority_section = convert_records_to_binary(records)
        additional_section = get_additional_section(domain_name)
        

        # Question Count (1 question)
        qdcount = b'\x00\x01'

        anscount = b'\x00\x00'
        authcount = len(records).to_bytes(2, byteorder='big')
        addcount = (len(additional_section) // 16).to_bytes(2, byteorder="big")

        # DNS header (Transaction ID, Flags, Question Count, Answer Count, Authority Count, Additional Count)
        dns_header = transaction_id + flags + qdcount + anscount + authcount + addcount
 
        response = dns_header + question_section + authority_section + additional_section

        return response
    else:
        error_response = build_error_response(data,Rcode)
        return error_response

#######################################################################################################

def handle_client(data, addr):
    print(f"TLD received data from Resolver: {data}")

    # Process the query
    response = build_response(data)

    # Send the response back to the resolver
    sock.sendto(response, addr)
    print(f"Sent response {response} to resolver")

while True:
    data, addr = sock.recvfrom(512)
    
    # Create a new thread for each request
    threading.Thread(target=handle_client, args=(data, addr)).start()
   


    

