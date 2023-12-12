import pickle
import socket
from util.RSA import RSA

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((socket.gethostname(), 8080))

# [1st STEP]: Share Public Key to Server
public_key_client, private_key_client = RSA.generate_keys()  # Client generates its own keys
print("Public Key [CLIENT] : ", public_key_client)
print("Private Key [CLIENT] : ", private_key_client)
public_key_client_serialized = pickle.dumps(public_key_client)
client_socket.send(public_key_client_serialized)

while True:
    # get ip_addr from server
    encrypted_ip_addr = client_socket.recv(4096)
    encrypted_ip_addr = pickle.loads(encrypted_ip_addr)
    # print(f"Encrypt [IP ADDR]: {encrypted_ip_addr}")
    decrypted_ip_addr = RSA.decrypt(encrypted_ip_addr, private_key_client)
    print(f"Decrypt [IP ADDR]: {decrypted_ip_addr}")
    ip_addr = decrypted_ip_addr # ip_addr is ip address 

    # get N1 from server
    encrypted_n1 = client_socket.recv(4096)
    encrypted_n1 = pickle.loads(encrypted_n1)
    # print(f"ENCRYPTED [N1]: {encrypted_n1}")
    decrypted_n1 = RSA.decrypt(encrypted_n1, private_key_client)
    print(f"Decrypt [N1]: {decrypted_n1}")