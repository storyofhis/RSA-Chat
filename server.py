import hashlib
import socket
import pickle
from DES.DES import DES
from RSA.RSA import RSA

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP = socket.gethostname()
PORT = 8080
server_socket.bind((IP, PORT))  # Ganti 'localhost' dengan alamat IP server jika perlu
server_socket.listen(5)

print("Server sudah siap, menunggu koneksi...")
ip_addr = f"{IP}:{PORT}"
print(f"{ip_addr}")

N1 = hashlib.sha256("t442743h38r4re733e2939u3423".encode()).hexdigest()
print("N1 : ", N1)

public_key_server, private_key_server = RSA.generate_keys()
print("Public Key [SERVER] : ", public_key_server)
print("Private Key [SERVER] : ", private_key_server)

while True:
    client_socket, client_address = server_socket.accept()
    public_key_server_serialized = pickle.dumps(public_key_server)
    client_socket.send(public_key_server_serialized)
    # get receive public_key_client
    public_key_client_serialized = client_socket.recv(4096)
    public_key_client = pickle.loads(public_key_client_serialized)
    
    print(f"Public Key [CLIENT] : {public_key_client}")
    print(f"Koneksi dari {client_address} telah diterima.")

    # send IP address to client
    encrypted_ip_addr = RSA.encrypt(ip_addr, public_key_client)
    # print(f"ENCRYPTED [IP ADDR]: {encrypted_ip_addr}")

    ip_addr_send = pickle.dumps(encrypted_ip_addr)
    client_socket.send(ip_addr_send)

    # send N1 to client
    encrypted_n1 = RSA.encrypt(N1, public_key_client)
    # print(f"ENCRYPTED [N1]: {encrypted_n1}")

    n1_send = pickle.dumps(encrypted_n1)
    client_socket.send(n1_send)

    # [2nd STEP] : receive N2 and N1 from client
    # Receive N1 encrypted from client
    encrypted_n1 = client_socket.recv(4096)
    encrypted_n1 = pickle.loads(encrypted_n1)
    decrypted_n1 = RSA.decrypt(encrypted_n1, private_key_server)
    print(f"Decrypted [N1]: {decrypted_n1}")
    # Receive N2 from client
    encrypted_n2 = client_socket.recv(4096)
    encrypted_n2 = pickle.loads(encrypted_n2)
    decrypted_n2 = RSA.decrypt(encrypted_n2, private_key_server)
    print(f"Decrypted [N2]: {decrypted_n2}")

    # [3rd STEP] : check if N1 == N1 Decrypted ??
    if decrypted_n1 == N1: 
        # send Decrypted N2 to Client
        encrypted_n2 = RSA.encrypt(decrypted_n2, public_key_client)
        n2_send = pickle.dumps(encrypted_n2)
        client_socket.send(n2_send)

        # [4 th STEP] : DES communication
        des_key = 17336
        des = DES(key = int(des_key))

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

            

        