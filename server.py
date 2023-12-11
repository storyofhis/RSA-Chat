from random import randint
import socket

# Fungsi untuk mengecek bilangan prima
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):  # Memperbaiki range untuk memeriksa prima
        if n % i == 0:
            return False
    return True

# Fungsi untuk menemukan FPB (Faktor Persekutuan Terbesar)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Fungsi untuk menghasilkan bilangan prima secara acak
def generate_prime():
    prime = randint(100, 200)  # Menghasilkan bilangan prima dalam rentang 100-200
    while not is_prime(prime):
        prime += 1
    return prime

# Fungsi untuk menghasilkan kunci RSA
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e += 1

    # Menggunakan invers modulo untuk mendapatkan nilai d
    d = pow(e, -1, phi)

    return (e, n), (d, n)

# Fungsi untuk enkripsi pesan menggunakan kunci publik
def encrypt(message, public_key):
    e, n = public_key
    cipher_text = [pow(ord(char), e, n) for char in message]
    return cipher_text

# Fungsi untuk dekripsi pesan menggunakan kunci privat
def decrypt(cipher_text, private_key):
    d, n = private_key
    plain_text = ''.join([chr(pow(char, d, n)) for char in cipher_text])
    return plain_text

def main():
    s = socket.socket()
    host = 'localhost'
    port = 8888
    s.bind((host, port))
    print('Waiting for connection...')
    s.listen(1)
    conn, addr = s.accept()
    public_key, private_key = generate_keys()
    
    while True:
        incoming_message = conn.recv(1024)
        if not incoming_message:
            break

        chipertext_list = [int(x) for x in incoming_message.split(b',') if x]
        decrypted_incoming_message = decrypt(chipertext_list, private_key)
        print("Client:", decrypted_incoming_message)

        message = input(">> ")
        encrypted_message = encrypt(message, public_key)
        encrypted_message_bytes = b','.join(str(x).encode() for x in encrypted_message)
        conn.send(encrypted_message_bytes)
    conn.close()

if __name__ == "__main__":
    main()
