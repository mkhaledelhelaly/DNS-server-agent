import socket

root_ip = '127.0.0.1'
root_port = 5353

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((root_ip, root_port))

def get_root(binary_domain_name):
    idx = 0
    last_label = b''

    while binary_domain_name[idx] != 0:  # Iterate until the null byte
        label_length = binary_domain_name[idx]  # Get the length of the current label
        last_label = binary_domain_name[idx:idx + label_length + 1]  # Extract the current label
        idx += label_length + 1  # Move to the next label

    return last_label  # Return the last label


while True:
    binary_domain_name, addr = sock.recvfrom(512)
    print(f"Root Server received domain name: {binary_domain_name}")
    
    root_label = get_root(binary_domain_name)
    print(f"Root Label = {root_label}")
    
    sock.sendto(root_label, addr)
    print(f"Root Server sent response")