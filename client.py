import pickle
import socket
from util.RSA import RSA

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((socket.gethostname(), 8080))

public_key_serialized = client_socket.recv(4096)
public_key = pickle.loads(public_key_serialized)
print("Public Key from Server:", public_key)
_, private_key = RSA.generate_keys()  # Client generates its own keys

while True:
    message = input("Masukkan pesan untuk server: ")
    if message == 'exit':
        break
    
    pesan_terenkripsi = RSA.encrypt(message, public_key)
    print("Message Encryption: ", pesan_terenkripsi)
    
    client_send = pickle.dumps(pesan_terenkripsi)
    client_socket.send(client_send)

    encrypted_data = client_socket.recv(4096)
    if not encrypted_data:
        print("Koneksi ditutup.")
        break
    
    encrypted_message = pickle.loads(encrypted_data)
    print(f"Encrypt [SERVER]: {encrypted_message}")

    # Decrypt the message from the server using client's private key
    decrypted_message = RSA.decrypt(encrypted_message, private_key)
    print(f"Decrypt [SERVER]: {decrypted_message}")
