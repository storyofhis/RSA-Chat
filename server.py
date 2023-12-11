import pickle
import socket
from DES.DES import DES
from util.RSA import RSA

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 8080))
server_socket.listen(5)
print("Server sudah siap, menunggu koneksi...")

# RSA algorithm
public_key, private_key = RSA.generate_keys()
print("Public Key : ", public_key)
print("Private Key : ", private_key)

des = DES(key=int(public_key)) # use public_key in RSA Algorithm

while True:
    public_key_serialized = pickle.dumps(public_key)
    client_socket, client_address = server_socket.accept()
    print(f"Koneksi dari {client_address} telah diterima.")
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
