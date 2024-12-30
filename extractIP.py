def extract_ip_from_response(root_response):
    """
    Extract IP address from the additional section of a DNS root response.
    Assumes exactly 1 question, 0 answers, 1 NS record, and 1 IP address in additional section.
    
    Args:
        root_response (bytes): The complete DNS root response
        
    Returns:
        str: The IP address in dot-decimal notation
    """
    # Skip the header (12 bytes)
    pointer = 12
    
    # Skip the question section
    # Find the end of the domain name
    while root_response[pointer] != 0:
        pointer += 1
    # Skip null byte and QTYPE/QCLASS (5 bytes total)
    pointer += 5
    
    # Skip the NS record in authority section
    # First find the end of the domain name
    while root_response[pointer] != 0:
        pointer += 1
    # Skip null byte and NS record fields (type, class, TTL, rdlength, rdata)
    pointer += 1  # null byte
    pointer += 2  # type
    pointer += 2  # class
    pointer += 4  # TTL
    rdlength = int.from_bytes(root_response[pointer:pointer+2], 'big')
    pointer += 2  # rdlength
    pointer += rdlength  # skip rdata
    
    # Now we're at the additional section
    # Skip the name compression pointer (2 bytes)
    pointer += 2
    # Skip type, class, TTL (8 bytes)
    pointer += 8
    # Skip rdlength (2 bytes)
    pointer += 2
    
    # Extract the 4 bytes of IP address
    ip_bytes = root_response[pointer:pointer+4]
    return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"


response = b'\x00\x02\x80\x00\x00\x01\x00\x00\x00\x01\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\x03com\x00\x00\x02\x00\x01\x00\x00\x0e\x10\x00\x14\x03ns1\x07tld-com\x06server\x00\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01'
ip = extract_ip_from_response(response)
print(ip)