import socket

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def decrypt(cipher_text, private_key):
    d, n = private_key
    plain_text = ''.join([chr(pow(char, d, n)) for char in cipher_text])
    return plain_text

def encrypt(message, public_key):
    e, n = public_key
    cipher_text = [pow(ord(char), e, n) for char in message]
    return cipher_text



def main():
    s = socket.socket()
    host = 'localhost'
    port = 8888

    s.connect((host, port))
    public_key = (101, 2539)  # Replace this with the server's public key

    while True:
        message = input(">> ")
        encrypted_message = encrypt(message, public_key)
        encrypted_message_bytes = b','.join(str(x).encode() for x in encrypted_message)
        s.send(encrypted_message_bytes)

        incoming_message = s.recv(1024)
        chipertext_list = [int(x) for x in incoming_message.split(b',') if x]
        decrypted_incoming_message = decrypt(chipertext_list, (1019, 2539))  # Replace with client's private key
        print("Server:", decrypted_incoming_message)

    s.close()
    
if __name__ == "__main__":
    main()
