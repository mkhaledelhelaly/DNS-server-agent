import socket
import logging
import threading

auth_ip = '127.0.0.1'
auth_port = 5357

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((auth_ip, auth_port))

auth_database = {
   "example.com": {
        "A": [
            {"value": "192.0.2.1", "ttl": 3600},  # A record for example.com
        ],
        "AAAA": [
            {"value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ttl": 3600},  # IPv6 address for example.com
        ],
        "PTR": [
            {"value": "example.com", "ttl": 3600},  # Reverse DNS record for 192.0.2.1
        ],
        "SOA": [
            {
                "primary_ns": "ns1.example.com",
                "admin_email": "admin.example.com",
                "serial": 2024122701,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600,
                "ttl": 3600,
            }
        ],
        "TXT": [
            {"value": "v=spf1 include:_spf.example.com ~all", "ttl": 3600},  # SPF record for email authentication
            {"value": "google-site-verification=1234567890abcdef", "ttl": 3600},  # Google site verification
        ],
        "SRV": [
            {
                "service": "_sip._tcp",
                "priority": 10,
                "weight": 5,
                "port": 5060,
                "target": "sip.example.com",
                "ttl": 3600,
            },
            {
                "service": "_ldap._tcp",
                "priority": 10,
                "weight": 5,
                "port": 389,
                "target": "ldap.example.com",
                "ttl": 3600,
            },
        ],
        "CAA": [
            {"tag": "issue", "value": "letsencrypt.org", "ttl": 3600},  # Allow Let's Encrypt to issue certificates
            {"tag": "iodef", "value": "mailto:security@example.com", "ttl": 3600},  # Incident reporting
        ],
        "MX": [
            {"value": "mail.example.com", "priority": 10, "ttl": 3600},  # MX record for example.com
        ],
        "CNAME": [
            {"alias": "www.example.com", "value": "example.com", "ttl": 3600},  # CNAME for www.example.com
        ],
    },

     "example.org": {
        "A": [
            {"value": "198.51.100.2", "ttl": 3600},  # A record for example.org
        ],
        "AAAA": [
            {"value": "2001:0db8:85a3:0000:0000:8a2e:0370:7335", "ttl": 3600},  # IPv6 address for example.org
        ],
        "PTR": [
            {"value": "example.org", "ttl": 3600},  # Reverse DNS record for 198.51.100.2
        ],
        "SOA": [
            {
                "primary_ns": "ns1.example.org",
                "admin_email": "admin.example.org",
                "serial": 2024122702,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600,
                "ttl": 3600,
            }
        ],
        "TXT": [
            {"value": "v=spf1 include:_spf.example.org ~all", "ttl": 3600},  # SPF record for email authentication
            {"value": "google-site-verification=abcdef1234567890", "ttl": 3600},  # Google site verification
        ],
        "SRV": [
            {
                "service": "_sip._tcp",
                "priority": 10,
                "weight": 5,
                "port": 5060,
                "target": "sip.example.org",
                "ttl": 3600,
            },
            {
                "service": "_ldap._tcp",
                "priority": 10,
                "weight": 5,
                "port": 389,
                "target": "ldap.example.org",
                "ttl": 3600,
            },
        ],
        "CAA": [
            {"tag": "issue", "value": "digicert.com", "ttl": 3600},  # Allow DigiCert to issue certificates
            {"tag": "iodef", "value": "mailto:security@example.org", "ttl": 3600},  # Incident reporting
        ],
        "MX": [
            {"value": "mail.example.org", "priority": 10, "ttl": 3600},  # MX record for example.org
        ],
        "CNAME": [
            {"alias": "www.example.org", "value": "example.org", "ttl": 3600},  # CNAME for www.example.org
        ],
    },

    "example.net": {
        "A": [
            {"value": "203.0.113.1", "ttl": 3600},  # A record for example.net
        ],
        "AAAA": [
            {"value": "2001:0db8:85a3:0000:0000:8a2e:0370:7336", "ttl": 3600},  # IPv6 address for example.net
        ],
        "PTR": [
            {"value": "example.net", "ttl": 3600},  # Reverse DNS record for 203.0.113.1
        ],
        "SOA": [
            {
                "primary_ns": "ns1.example.net",
                "admin_email": "admin.example.net",
                "serial": 2024122703,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600,
                "ttl": 3600,
            }
        ],
        "TXT": [
            {"value": "v=spf1 include:_spf.example.net ~all", "ttl": 3600},  # SPF record for email authentication
            {"value": "facebook-site-verification=123456abcdef", "ttl": 3600},  # Facebook site verification
        ],
        "SRV": [
            {
                "service": "_sip._tcp",
                "priority": 20,
                "weight": 10,
                "port": 5060,
                "target": "sip.example.net",
                "ttl": 3600,
            },
            {
                "service": "_ftp._tcp",
                "priority": 15,
                "weight": 5,
                "port": 21,
                "target": "ftp.example.net",
                "ttl": 3600,
            },
        ],
        "CAA": [
            {"tag": "issue", "value": "letsencrypt.org", "ttl": 3600},  # Allow Let's Encrypt to issue certificates
            {"tag": "iodef", "value": "mailto:admin@example.net", "ttl": 3600},  # Incident reporting
        ],
        "MX": [
            {"value": "mail.example.net", "priority": 10, "ttl": 3600},  # MX record for example.net
        ],
        "CNAME": [
            {"alias": "www.example.net", "value": "example.net", "ttl": 3600},  # CNAME for www.example.net
        ],
    },
}

#############################################################################################################################################################

###########################################################################################################################################

# Function to retrieve DNS record from the database
def get_records(domain_name, record_type):
    if domain_name in auth_database and record_type in auth_database[domain_name]:
        return auth_database[domain_name][record_type]
    return []

#######################################################################################################################################################3

# Function to build the DNS response body (resource records)
def build_records(domain_name, record_type, records):
    response_body = b""

    for record in records:
        ttl = record['ttl']
        

        if record_type == 'A':
            value = record['value']
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x01'
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')
            response_body += b'\x00\x04'

            ip_bytes = bytes(map(int, value.split('.')))
            response_body += ip_bytes

        elif record_type == 'AAAA':
            value = record['value']
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x00\x1c'  # Specifies the record type as AAAA (28)
            response_body += b'\x00\x01'  # Specifies Class IN (Internet)
            response_body += int(ttl).to_bytes(4, byteorder='big')  # TTL
            response_body += b'\x00\x10'  # Length of the address (16 bytes for type AAAA)

            # Convert the IPv6 address into 16 bytes
            import ipaddress
            ipv6_bytes = ipaddress.IPv6Address(value).packed
            response_body += ipv6_bytes

        elif record_type == 'CNAME':
            value = record['value']
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x05'
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')

            cname_labels = value.split('.')
            cname_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in cname_labels)
            cname_bytes += b'\x00'

            response_body += len(cname_bytes).to_bytes(2, byteorder='big')
            response_body += cname_bytes

        elif record_type == 'NS':
            value = record['value']
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x02'
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')

            ns_labels = value.split('.')
            ns_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in ns_labels)
            ns_bytes += b'\x00'

            response_body += len(ns_bytes).to_bytes(2, byteorder='big')
            response_body += ns_bytes

        elif record_type == 'MX':
            value = record['value']
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x0f'
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')

            priority = record['priority']
            mx_labels = value.split('.')
            mx_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in mx_labels)
            mx_bytes += b'\x00'

            response_body += (2 + len(mx_bytes)).to_bytes(2, byteorder='big')
            response_body += priority.to_bytes(2, byteorder='big')
            response_body += mx_bytes

        elif record_type == 'PTR':
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x0c'  # Specifies the record type as PTR (12)
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')

            ptr_labels = value.split('.')
            ptr_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in ptr_labels)
            ptr_bytes += b'\x00'

            response_body += len(ptr_bytes).to_bytes(2, byteorder='big')
            response_body += ptr_bytes

        elif record_type == 'SOA':
            # SOA records have specific fields instead of a generic 'value'
            response_body += b'\xc0\x0c'  # Pointer to domain name in the question section

            response_body += b'\x00\x06'  # SOA record type (6)
            response_body += b'\x00\x01'  # Class (IN - Internet)
            response_body += int(ttl).to_bytes(4, byteorder='big')  # TTL as a 4-byte integer

            # Extract SOA-specific fields
            primary_ns = record['primary_ns']
            admin_email = record['admin_email']
            serial = record['serial']
            refresh = record['refresh']
            retry = record['retry']
            expire = record['expire']
            minimum = record['minimum']

            # Split mname (primary nameserver) into labels
            mname_labels = primary_ns.split('.')
            # Split rname (responsible party's email) into labels, replace '.' with a separator
            rname_labels = admin_email.replace('.', '@').split('@')

            # Encoding for mname (Primary nameserver)
            soa_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in mname_labels)
            soa_bytes += b'\x00'  # Null byte to terminate the mname (primary nameserver)

            # Encoding for rname (Responsible party's email)
            soa_bytes += b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in rname_labels)
            soa_bytes += b'\x00'  # Null byte to terminate the rname (email address)

            # Add SOA-specific fields: serial, refresh, retry, expire, minimum TTL
            soa_bytes += int(serial).to_bytes(4, byteorder='big')  # Serial number
            soa_bytes += int(refresh).to_bytes(4, byteorder='big')  # Refresh interval
            soa_bytes += int(retry).to_bytes(4, byteorder='big')  # Retry interval
            soa_bytes += int(expire).to_bytes(4, byteorder='big')  # Expiry interval
            soa_bytes += int(minimum).to_bytes(4, byteorder='big')  # Minimum TTL

            # Length of the SOA record in bytes (the total size of soa_bytes)
            response_body += len(soa_bytes).to_bytes(2, byteorder='big')  # Length of SOA data

            # Append the actual SOA data
            response_body += soa_bytes

        elif record_type == 'TXT':
            value = record['value']
            response_body += b'\xc0\x0c'
            response_body += b'\x00\x10'  # Specifies the record type as TXT (16)
            response_body += b'\x00\x01'
            response_body += int(ttl).to_bytes(4, byteorder='big')

            txt_bytes = len(value).to_bytes(1, byteorder='big') + value.encode()

            response_body += len(txt_bytes).to_bytes(2, byteorder='big')
            response_body += txt_bytes

        elif record_type == 'SRV':
            service = record['service']
            priority = record['priority']
            weight = record['weight']
            port = record['port']
            target = record['target']
            ttl = record['ttl']

            # Combine service and domain into the full SRV record name
            service_domain = f"{service}.{domain_name}"

            # Encode the service.domain labels
            service_labels = service_domain.split('.')
            service_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in service_labels)
            service_bytes += b'\x00'  # Null byte to terminate the service domain name

            # Encode the target labels
            target_labels = target.split('.')
            target_bytes = b"".join(len(label).to_bytes(1, byteorder='big') + label.encode() for label in target_labels)
            target_bytes += b'\x00'  # Null byte to terminate the target domain name

            # Add the record to the response body
            response_body += b'\xc0\x0c'  # Pointer to the domain name in the question section
            response_body += b'\x00\x21'  # Specifies the record type as SRV (33)
            response_body += b'\x00\x01'  # Class IN (Internet)
            response_body += int(ttl).to_bytes(4, byteorder='big')  # TTL

            # Calculate the total length of the SRV record data
            srv_data_length = 6 + len(target_bytes)
            response_body += srv_data_length.to_bytes(2, byteorder='big')  # Data length

            # Append SRV-specific fields
            response_body += priority.to_bytes(2, byteorder='big')  # Priority
            response_body += weight.to_bytes(2, byteorder='big')  # Weight
            response_body += port.to_bytes(2, byteorder='big')  # Port
            response_body += target_bytes  # Target hostname


        elif record_type == 'CAA':
            # CAA record structure
            response_body += b'\xc0\x0c'  # Pointer to the domain name
            response_body += b'\x01\x01'  # Specifies the record type as CAA (257)
            response_body += b'\x00\x01'  # Class IN (Internet)
            response_body += int(ttl).to_bytes(4, byteorder='big')  # TTL

            # Parse CAA fields: flags, tag, and value
            flags = record.get('flags', 0)  # Default flags to 0 if not provided
            tag = record['tag']
            value = record['value'].encode()

            # Encode the tag and value fields
            tag_bytes = len(tag).to_bytes(1, byteorder='big') + tag.encode()
            value_length = len(tag_bytes) + len(value) + 1  # Total length of CAA data

            # Append data length
            response_body += value_length.to_bytes(2, byteorder='big')  # Length of CAA data
            response_body += flags.to_bytes(1, byteorder='big')  # Flags
            response_body += tag_bytes  # Tag field
            response_body += value  # Value field
    return response_body
    
####################################################################################################################################################3
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
    255: 'ANY',
    257: 'CAA'
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
####################################################################################################################################################

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
    # print(f"Rcode (binary) = {Rcode}")

    # Concatenate all the parts into a single binary string
    flags = QR + opcode + AA + TC + RD + RA + Z + str(Rcode)

    # Convert the binary string to an integer, then to bytes
    flags = int(flags, 2).to_bytes(2, byteorder='big')
    return flags
##########################################################################################################################

def get_rcode(domain_name, query_type, data):
    if not validate_query_format(data):
        return 1  # FORMERR
    if query_type not in ['A', 'CNAME', 'MX', 'NS','AAAA','PTR', 'TXT', 'SOA', 'SRV','CAA']:
        return 4  # NOTIMP
    if domain_name not in auth_database:
        return 3  # NXDOMAIN
    return 0  # NOERROR

    # 2 -> server failure
    # 5 -> policy restriction
##############################################################################################################################

# Validate and sanitize incoming DNS queries
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

###################################################################################################################

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
##################################################################################################################

def build_response(data):
    # Extract domain name and query type from the question section
    domain_name, query_type = get_question_domain(data)
    print(f"Domain Name = {domain_name}")

    records = get_records(domain_name,query_type, )
    print(f"records = {records}")

    # Transaction ID (from the original query)
    transaction_id = data[:2]


    Rcode = f"{get_rcode(domain_name, query_type, data):04b}"
    # Flags (standard query response)
    flags = get_flags(Rcode)
    

    if Rcode =='0000':
        # Question Count (1 question)
        qdcount = b'\x00\x01'

        # Answer Count (how many answers are being returned)
        anscount = anscount = len(records).to_bytes(2, byteorder='big') 

        # No additional authority or additional records
        authcount =b'\x00\x00'
        addcount = b'\x00\x00'

        # DNS header (Transaction ID, Flags, Question Count, Answer Count, Authority Count, Additional Count)
        dns_header = transaction_id + flags + qdcount + anscount + authcount + addcount

        # DNS question section (domain name and query type)
        question_section = data[12:]  # The Question Section in a response is an echo of the question from the request.

        answer_section = build_records(domain_name, query_type, records)

        response = dns_header + question_section + answer_section

        return response
    
    else:
        error_response = build_error_response(data,Rcode)
        return error_response
#########################################################################################################################

def handle_client(data, addr):
    print(f"Received data: {data} from {addr}")

    # Process the query
    response = build_response(data)

    # Send the response back to the resolver
    sock.sendto(response, addr)
    print(f"Sent response {response} to resolver")

while True:
    data, addr = sock.recvfrom(512)
    
    # Create a new thread for each request
    threading.Thread(target=handle_client, args=(data, addr)).start()
    