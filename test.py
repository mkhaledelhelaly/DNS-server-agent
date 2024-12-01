import socket

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip,port))


dns_database = {
    "example.com": {
        "A": [
            {"value": "127.0.0.1", "tt1": 3600}
        ]
        
    },
    "anotherdomain.com": {
        "A": [
            {"value": "192.168.1.1", "tt1": 3600}
        ]
    }
}


def getflags(flags):
  
    QR = '1' #response message
    opcode = '0000' #Standard query

    # for bit in range(1,5):
    #     opcode += str(ord(byte1)&(1<<bit))

    AA = '1' #This is an authoritative servee
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    Rcode = '0000'
    flags = int(QR + opcode + AA + TC+ RD ,2).to_bytes(1, byteorder = 'big') + int(RA + Z + Rcode,2).to_bytes(1,byteorder='big')

    return flags


def getQuestionDomain(data):
    state = 0
    expecctedlength = 0
    domainstring = '' #build current domain label
    domainparts = [] #store complete labels

    x =0 # Counter to track the number of characters processed for the current label.
    y = 0 #Counter to track the total bytes processed.

    for byte in data: #Iterates over each byte in the data sequence
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x+=1
            if x == expecctedlength:
                domainparts.append(domainstring) #If x equals the expected length, add string to domainparts. Reset domain string and x
                domainstring = ''
                state = 0
                x = 0
            if byte == 0: #If the byte is 0, it signals the end of the domain name
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expecctedlength = byte
        y+=1

    questiontype = data[y:y+2] #Extracts two bytes following the domain name, which specify the query type 
    return (domainparts,questiontype)


def getzone(domain):
    global dns_database
    zone_name = '.'.join(domain)
    return dns_database.get(zone_name, {})


def getrecs(data):
    domain, questiontype = getQuestionDomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'A'
    elif questiontype == b'\x00\x05':
        qt = 'CNAME'
    elif questiontype == b'\x00\x0F':
        qt = 'MX'
    elif questiontype == b'\x00\x02':
        qt = 'NS'

    zone = getzone(domain)
    
    if not zone or qt not in zone:
        return [], qt, domain  # No records found
    
    records = zone.get(qt,[])
    return records, qt, domain


def buildquestion(domainname,rectype):
    qbytes =b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder = 'big')
        
        if rectype == 'a':
            qbytes += ord(char).to_bytes(1, byteorder = 'big')

        qbytes += (1).to_bytes(2, byteorder = 'big')

        return qbytes


def rectobytes(domainname, rectype,rectt1,recval):
    rbytes = b'\xc0\x0c' #This is a pointer to a previous part of the DNS message.
    if rectype == 'a':
        rbytes = rbytes+bytes([0])+bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes += int(rectt1).to_bytes(4,byteorder='big')

    if rectype =='a':
        rbytes = rbytes + bytes([0]) + bytes([4])
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes


def buildresponse(data):

    #Extracts the first 2 bytes from the incoming DNS query
    #This ensures the response uses the same Transaction ID as the original query
    TransactionID = data[:2] 

    Flags = getflags(data[2:4]) #Flags = X8600
    print(f"flags: {Flags}")

    #Sets Question Count to 1 (hardcoded bytes)
    # Indicates there's one question in the response
    QDCOUNT = b'\x00\x01'


    records, rectype, domainname = getrecs(data[12:])
    print(f"Domain name: {domainname}")
    print(f"Query Type: {rectype}")


    ANCOUNT = len(records).to_bytes(2, byteorder='big')
    print(f"answer count = {ANCOUNT}")

    #Set them to 0
    NSCOUNT = (0).to_bytes(2,byteorder='big') #Authority count
    ARCOUNT = (0).to_bytes(2, byteorder='big') #Additional count


    dnsheader = TransactionID + Flags + QDCOUNT+ ANCOUNT+ NSCOUNT+ ARCOUNT
    dnsquestion = buildquestion(domainname, rectype)
    print(f"DNS header: {dnsheader}")
    print(f"DNS question: {dnsquestion}")

    dnsbody = b''
    
    for record in records:
        dnsbody  += rectobytes(domainname, rectype,record["tt1"], record["value"])
    
    print(f"DNS body: {dnsbody}")
    
    return dnsheader + dnsquestion + dnsbody




while 1:
    data,addr = sock.recvfrom(512)
    print(data)
    r = buildresponse(data)
    print(f"R: {r}")
    sock.sendto(r, addr)
