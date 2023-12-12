import hashlib
import pickle
import socket
from util.RSA import RSA

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((socket.gethostname(), 8080))

# [1st STEP]: Share Public Key to Server
public_key_client, private_key_client = RSA.generate_keys()  # Client generates its own keys


public_key_server_serialized = client_socket.recv(4096)
public_key_server = pickle.loads(public_key_server_serialized)
print(f"Public Key [SERVER] : {public_key_server}")

print("Public Key [CLIENT] : ", public_key_client)
print("Private Key [CLIENT] : ", private_key_client)
public_key_client_serialized = pickle.dumps(public_key_client)
client_socket.send(public_key_client_serialized)

N2 = hashlib.sha256("t332743h38r4re733X8473b2948".encode()).hexdigest()
print("N2 : ", N2)

while True:
    # get ip_addr from server
    encrypted_ip_addr = client_socket.recv(4096)
    encrypted_ip_addr = pickle.loads(encrypted_ip_addr)
    # print(f"Encrypt [IP ADDR]: {encrypted_ip_addr}")
    decrypted_ip_addr = RSA.decrypt(encrypted_ip_addr, private_key_client)
    print(f"Decrypt [IP ADDR]: {decrypted_ip_addr}")
    ip_addr = decrypted_ip_addr # ip_addr is ip address 

    # public_key_server_serialized = client_socket.recv(4096)
    # public_key_server = pickle.loads(public_key_server_serialized)
    # print(f"Public Key [SERVER] : {public_key_server}")

    # get N1 from server
    encrypted_n1 = client_socket.recv(4096)
    encrypted_n1 = pickle.loads(encrypted_n1)
    # print(f"ENCRYPTED [N1]: {encrypted_n1}")
    decrypted_n1 = RSA.decrypt(encrypted_n1, private_key_client)
    print(f"Decrypt [N1]: {decrypted_n1}")

    # [2nd STEP] : send N2 and N1 to server
    # send N1 to server
    encrypted_n1 = RSA.encrypt(decrypted_n1, public_key_server)
    print(f"ENCRYPTED [N1]: {encrypted_n1}")
    n1_send = pickle.dumps(encrypted_n1)
    client_socket.send(n1_send)

    # send N2 to server
    encrypted_n2 = RSA.encrypt(N2, public_key_server)
    print(f"ENCRYPTED [N2]: {encrypted_n2}")
    n2_send = pickle.dumps(encrypted_n2)
    client_socket.send(n2_send)

    # [3rd STEP] : 
    # receive encrypted N2 from Server
    encrypted_n2 = client_socket.recv(4096)
    encrypted_n2 = pickle.loads(encrypted_n2)
    decrypted_n2 = RSA.decrypt(encrypted_n2, private_key_client)
    print(f"Decrypted [N2]: {decrypted_n2}")


