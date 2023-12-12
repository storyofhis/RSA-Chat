import hashlib
import socket
import pickle
from util.RSA import RSA

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

while True:
    public_key_server, private_key_server = RSA.generate_keys()
    print("Public Key [SERVER] : ", public_key_server)
    print("Private Key [SERVER] : ", private_key_server)
    
    client_socket, client_address = server_socket.accept()
    # get receive public_key_client
    public_key_client_serialized = client_socket.recv(4096)
    public_key_client = pickle.loads(public_key_client_serialized)
    
    print(f"Public Key [CLIENT] : {public_key_client}")
    print(f"Koneksi dari {client_address} telah diterima.")

    # send IP address to client
    encrypted_ip_addr = RSA.encrypt(ip_addr, public_key_client)
    print(f"ENCRYPTED [IP ADDR]: {encrypted_ip_addr}")

    ip_addr_send = pickle.dumps(encrypted_ip_addr)
    client_socket.send(ip_addr_send)

    # send N1 to client
    encrypted_n1 = RSA.encrypt(N1, public_key_client)
    print(f"ENCRYPTED [N1]: {encrypted_n1}")

    n1_send = pickle.dumps(encrypted_n1)
    client_socket.send(n1_send)
