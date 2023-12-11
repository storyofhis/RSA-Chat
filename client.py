import pickle
import socket
from DES.DES import DES
from util.RSA import RSA

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 8080))

# RSA algorithm
public_key_serialized = client_socket.recv(4096)
public_key = pickle.loads(public_key_serialized)
print("Public Key from Server:", public_key)
_, private_key = RSA.generate_keys()  # Client generates its own keys

des = DES(key=int(public_key)) # use public_key in RSA Algorithm

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
