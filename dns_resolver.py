import socket
import threading
import logging

# Resolver details
resolver_ip = '127.0.0.1'

@@ -14,6 +15,9 @@ auth_port = 5357
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((resolver_ip, resolver_port))

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

#Lock for thread synchronization
lock = threading.Lock()



@@ -92,13 +96,13 @@ def check_for_error(response):
    rcode = flags_int & 0b1111  # Mask the last 4 bits

    if rcode == 0:
        print("No error found in Query")
        logging.info("No error found in Query")
    elif rcode == 1:
        print("RCODE = 1: Format Error in Query sent to server")
        logging.warning("RCODE = 1: Format Error in Query sent to server")
    elif rcode == 3:
        print("RCODE = 3: Non-Existent Domain")
        logging.warning("RCODE = 3: Non-Existent Domain")
    elif rcode ==4:
        print("RCODE = 4: Unsupported Query Type")
        logging.warning("RCODE = 4: Unsupported Query Type")

    return response


@@ -112,43 +116,43 @@ def handle_query(data, addr):
        if b'\x04arpa\x00' in binary_domain_name:
            return  # Reject reverse lookup for ARPA domains

        print(f"Binary Domain Name = {binary_domain_name}")
        print(f"Resolver received data from client: {data}")
        logging.info(f"Binary Domain Name = {binary_domain_name}")
        logging.info(f"Resolver received data from client: {data}")
        
        # ROOT SERVER
        # with lock:
        print("\n\nROOT SERVER:")
        sock.sendto(data, (root_ip, root_port))
        print(f"Resolver sent data {data} to root server")
        logging.info(f"Resolver sent data {data} to root server")
        root_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from root: {root_response}")
        logging.info(f"Resolver received response from root: {root_response}")
        root_response = check_for_error(root_response)
        
        # TLD SERVER
        # with lock:
        print("\n\nTLD SERVER:")
        tld_query = remove_ns_records_and_reset_qr(root_response)  # We are using constant IPs
        print(f"TLD Query: {tld_query}")
        logging.info(f"TLD Query: {tld_query}")
        sock.sendto(tld_query, (tld_ip, tld_port))
        print(f"Resolver sent data to TLD server: {root_response}")
        logging.info(f"Resolver sent data to TLD server: {root_response}")
        tld_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from TLD: {tld_response}")
        logging.info(f"Resolver received response from TLD: {tld_response}")
        tld_response = check_for_error(tld_response)
        
        # AUTHORITATIVE SERVER
        #with lock:
        print("\n\nAUHORITATIVE SERVER:")
        auth_query = remove_ns_records_and_reset_qr(tld_response)
        print(f"Authoritative Query: {auth_query}")
        logging.info(f"Authoritative Query: {auth_query}")
        sock.sendto(auth_query, (auth_ip, auth_port))
        print(f"Resolver sent data {auth_query} to authoritative server")
        logging.info(f"Resolver sent data {auth_query} to authoritative server")
        auth_response, _ = sock.recvfrom(512)
        print(f"Resolver received response from authoritative: {auth_response}")
        logging.info(f"Resolver received response from authoritative: {auth_response}")
        auth_response = check_for_error(auth_response)

        # Send the final response to the client
        sock.sendto(auth_response, addr)
        print(f"Resolver sent data back to client \n\n\n\n")
        logging.info(f"Resolver sent data back to client \n\n\n\n")

    finally:
        thread_sock.close() 

@@ -159,6 +163,6 @@ while True:
        data, addr = sock.recvfrom(512)
        handle_query(data, addr)

        # # Create a new thread for each incoming request
        # threading.Thread(target=handle_query, args=(data, addr)).start()
        # Create a new thread for each incoming request
        threading.Thread(target=handle_query, args=(data, addr)).start()