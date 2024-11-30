import socket, glob, json

from numpy import char

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip,port))

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zone/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()

def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    
    rfflags = ''
    QR = '1'
    opcode = ''

    for bit in range(1,5):
        opcode += str(ord(byte1)&(1<<bit))

    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    Rcode = '0000'

    return int(QR + opcode + AA + TC+ RD ,2).to_bytes(1, byteorder = 'big') + int(RA + Z + Rcode,2).to_bytes(1,byteorder='big')  

def getQuestionDomain(data):
    state = 0
    expecctedlength = 0
    domainstring = ''
    domainparts = []

    x =0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += char(byte)
            x+=1
            if x == expecctedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expecctedlength = byte
        y+=1
    questiontype  = data[y:y+2]
    return (domainparts,questiontype)

def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata[zone_name]


def getrecs(data):
    domain, questiontype = getQuestionDomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)
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
    rbytes = b'\xc0\x0c'
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
    TransactionID = data[:2]
    Flags = getflags(data[2:4])
    QDCOUNT = b'\x00\x01'
    ANCOUNT = len(getrecs())
    NSCOUNT = (0).to_bytes(2,byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsheader = TransactionID + Flags + QDCOUNT+ ANCOUNT+ NSCOUNT+ ARCOUNT

    dnsbody = b''

    records, rectype, domainname = getrecs(data[12:])

    dnsquestion = buildquestion(domainname, rectype)

    for record in records:
        dnsbody  += rectobytes(domainname, rectype,record["tt1"], record["value"])
    
    return dnsheader + dnsquestion + dnsbody

while 1:
    data,addr = sock.recvfrom(512)
    r = buildresponse(data)
    sock.sendto(r, addr)