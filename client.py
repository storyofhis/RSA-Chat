# [RESPONDER B]

import pickle
import socket
from DES.DES import DES
from util.RSA import RSA

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((socket.gethostname(), 8080))

# [1st STEP]: Share Public Key to Server
public_key_client, private_key_client = RSA.generate_keys()  # Client generates its own keys
print("Public Key [CLIENT] : ", public_key_client)
print("Private Key [CLIENT] : ", private_key_client)
public_key_client_serialized = pickle.dumps(public_key_client)
client_socket.send(public_key_client_serialized)

# receive step1 from server
# expected_data_size = 5917  
received_data = client_socket.recv(4096)
# encrypted_message = pickle.loads(received_data)
print("Encrypted [IP, PORT, N1] :", received_data)
decrypted_message = RSA.decrypt(received_data, int(private_key_client))
print("Decrypted [IP, PORT, N1] :", decrypted_message)

# RSA algorithm
public_key_serialized = client_socket.recv(4096)
public_key_server = pickle.loads(public_key_serialized)
print("Public Key from Server:", public_key_server)


des = DES(key=int(public_key_server)) # use public_key in RSA Algorithm

while True:
    message = input('>> ').encode()
    chipertext = des.encrypt_message(message.decode())
    
    # Serialize the list of integers to bytes
    chipertext_bytes = b','.join(str(x).encode() for x in chipertext)

    # Send encrypted message
    client_socket.send(chipertext_bytes)
    print("chipertext : ", chipertext)
    print("plaintext : ", message)
    print('Sent')

    # Receive response
    incoming_message = client_socket.recv(1024)
    incoming_message_bytes = incoming_message.split(b',')
    incoming_message_bytes = [x for x in incoming_message_bytes if x]
    print("chipertext from [SERVER]: ", incoming_message)
    # Decrypt the received ciphertext using DES
    decrypted_incoming_message = des.decrypt_message([int(x.decode()) for x in incoming_message_bytes])
    print('plainttext from [SERVER]:', decrypted_incoming_message)
    print()
