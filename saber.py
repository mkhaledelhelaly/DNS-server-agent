import socket


class DNSQuery:
    def __init__(self, data, db):
        self.data = data
        self.db = db
        self.domain_name = ''  # The domain name extracted from the query

        query_type = (data[2] >> 3) & 15  # Directly use data[2] as an integer
        print(data)  # Print the raw query data

        if query_type == 0:  # If it's a Standard Query (type 0)
            start_index = 12  # Starting index for the domain name in the query
            length = data[start_index]  # The length of the first part of the domain name
            while length != 0:  # Loop through the domain name parts
                self.domain_name += data[start_index + 1: start_index + length + 1].decode() + '.'  # Append domain part
                print(length)  # Print the length of the current domain part
                print(self.domain_name)  # Print the current accumulated domain name
                start_index += length + 1  # Move to the next part of the domain
                length = data[start_index]  # Get the length of the next domain part

    def generate_response(self, ip):
        packet = b''  # Start with an empty byte string
        if self.domain_name:
            packet += self.data[:2] + b"\x81\x80"  # Response flags (standard response)
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'  # Questions and Answers Counts
            packet += self.data[12:]  # Append the original Domain Name Question
            packet += b'\xc0\x0c'  # Pointer to the domain name (compression)
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, ttl, and resource data length (4 bytes)
            packet += bytes(
                map(lambda x: int(x), ip.split('.')))  # 4 bytes of the IP address (convert string IP to bytes)
        return packet


class SimpleDatabase:
    def __init__(self):
        # Simulated DNS database (domain -> IP address mapping)
        self.db = {
            "example.com": "93.184.216.34",
            "test.com": "192.0.2.1",
            "mywebsite.local": "127.0.0.1"
        }

    def resolve(self, domain_name):
        # Return the IP if found, else None
        return self.db.get(domain_name.strip('.'), None)


if __name__ == '__main__':
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('127.0.0.1', 53))  # Bind the socket to port 53 (DNS)

    db = SimpleDatabase()  # Instantiate the simple database

    try:
        while True:  # Infinite loop to handle requests
            data, client_address = udp_socket.recvfrom(1024)  # Receive the incoming DNS query
            query = DNSQuery(data, db)  # Parse the DNS query
            resolved_ip = db.resolve(query.domain_name)  # Try to resolve the domain name using the database
            if resolved_ip:
                print(f"Resolved {query.domain_name} to {resolved_ip}")
                udp_socket.sendto(query.generate_response(resolved_ip),
                                  client_address)  # Send the response with the IP address
            else:
                print(f"Domain {query.domain_name} not found in database")
                udp_socket.sendto(query.generate_response("0.0.0.0"), client_address)  # Send a "not found" response
            print(f"Response: {query.domain_name} -> {resolved_ip}")  # Print the response details
    except KeyboardInterrupt:
        print('Shutting down')  # Handle program termination
        udp_socket.close()  # Close the UDP socket
