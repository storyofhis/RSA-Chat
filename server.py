import socket
import pickle
from util.RSA import RSA

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((socket.gethostname(), 8080))  # Ganti 'localhost' dengan alamat IP server jika perlu
server_socket.listen(5)

print("Server sudah siap, menunggu koneksi...")


while True:
    # Use the appropriate private key to decrypt the message
    # private_key = RSA.load_private_key()  # Load the private key from your RSA module
    public_key,private_key = RSA.generate_keys()
    print("Public Key : ", public_key)
    print("Private Key : ", private_key)
    public_key_serialized = pickle.dumps(public_key)
    client_socket, client_address = server_socket.accept()
    print(f"Koneksi dari {client_address} telah diterima.")
    client_socket.send(public_key_serialized)

    while True:
        encrypted_data = client_socket.recv(4096)
        if not encrypted_data:  # Jika data kosong, maka putuskan koneksi
            print("Koneksi ditutup.")
            break

        encrypted_message = pickle.loads(encrypted_data)
        print(f"Encrypt [CLIENT]: {encrypted_message}")

        decrypted_message = RSA.decrypt(encrypted_message, private_key)
        print(f"Decrypt [CLIENT]: {decrypted_message}")

        # Now you can work with the decrypted message
        # For instance, you might send a response to the client
        message = input("Masukkan pesan untuk client: ")
        if message == 'exit':
            break
        pesan_terenkripsi = RSA.encrypt(message, public_key)
        print("Message Encryption : ", pesan_terenkripsi)
        server_send = pickle.dumps(pesan_terenkripsi)
        client_socket.send(server_send)

        if decrypted_message.lower() == 'exit':  # Menutup koneksi jika input 'exit'
            break
