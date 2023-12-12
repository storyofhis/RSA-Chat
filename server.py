import pickle
import socket
from DES.DES import DES
from util.RSA import RSA
import hashlib

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((socket.gethostname(), 8080))
server_socket.listen(5)
print("Server sudah siap, menunggu koneksi...")

# [1st STEP]
hostname = socket.gethostname()
ip_address = socket.gethostbyname(socket.gethostname())
print(f"HOSTNAME : {hostname}")
print(f"IP Address: {ip_address}")

n1 = "27345847"
print("N1 : ", n1)

while True:
    # RSA algorithm
    public_key, private_key = RSA.generate_keys()
    print("Public Key [SERVER]: ", public_key)
    print("Private Key [SERVER] : ", private_key)

    client_socket, client_address = server_socket.accept()
    # get receive public_key_client 
    public_key_client_serialized = client_socket.recv(4096)
    public_key_client = pickle.loads(public_key_client_serialized)
    print(f"Public Key [CLIENT] : {public_key_client}")
    print(f"Koneksi dari {client_address} telah diterima.")

    # send n1 to client  
    n1_bytes = pickle.dumps(n1)
    encrypted_n1 = RSA.encrypt(n1_bytes, int(public_key_client))
    print("Encrypted [N1] : ", encrypted_n1)
    client_socket.send(pickle.dumps(encrypted_n1))

    des = DES(key=int(public_key)) # use public_key in RSA Algorithm
    
    public_key_serialized = pickle.dumps(public_key)
    client_socket.send(public_key_serialized)

    while True:
        incoming_message = client_socket.recv(1024)
        if not incoming_message:
            break
        
        print("chipertext from [CLIENT]: ", incoming_message)
        chipertext_list = [int(x) for x in incoming_message.split(b',') if x]
        decrypted_incoming_message = des.decrypt_message(chipertext_list)

        print('plaintext from [CLIENT]:', decrypted_incoming_message)
        print()
        
        message = input('>> ').encode()
        chipertext = des.encrypt_message(message.decode())
    
        chipertext_bytes = b','.join(str(x).encode() for x in chipertext)
        client_socket.send(chipertext_bytes)

        print("chipertext : ", chipertext)
        print("plaintext : ", message)

        print('Sent')
        print()

    client_socket.close()
