import math
import random

class RSA:
    def is_prime(n):
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def generate_prime(bits=64):
        primes = []
        while len(primes) < 2:
            # Generate a random number of the specified number of bits
            num = random.getrandbits(bits)

            # Set the high bit to ensure that the number has the specified number of bits
            num |= 1 << bits - 1

            # Check if the number is prime
            if RSA.is_prime(num):
                if len(primes) == 1 and primes[0] == num:
                    continue
                primes.append(num)
        return primes[0], primes[1]

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    @staticmethod
    def generate_keys():
        # Generating prime numbers for key generation (normally done with larger primes)
        def generate_prime_number():
            return random.choice([i for i in range(50, 100) if all(i % n != 0 for n in range(2, int(math.sqrt(i)) + 1))])

        # Key generation
        p = generate_prime_number()
        q = generate_prime_number()

        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose a random integer 'e' that is coprime with phi
        e = random.randint(1, phi)
        while math.gcd(e, phi) != 1:
            e = random.randint(1, phi)

        # Calculate the modular inverse of 'e'
        d = pow(e, -1, phi)

        # Convert keys to string representation of integers
        public_key = str(n)
        private_key = str(d)

        return public_key, private_key
    
    # Fungsi untuk enkripsi pesan
    def encrypt(message, public_key):
        e, N = public_key
        encrypted_msg = [pow(ord(char), e, N) for char in message]
        return encrypted_msg

    # Fungsi untuk dekripsi pesan
    def decrypt(encrypted_msg, private_key):
        d, N = private_key
        decrypted_msg = ''.join([chr(pow(char, d, N)) for char in encrypted_msg])
        return decrypted_msg

