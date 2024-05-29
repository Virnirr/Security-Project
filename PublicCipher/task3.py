import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def generate_rsa_keys(bits=2048):
    e = 65537
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return (n, e), (n, d)

def rsa_encrypt(message, pubkey):
    n, e = pubkey
    m = bytes_to_long(message)
    c = pow(m, e, n)
    return c

def rsa_decrypt(ciphertext, privkey):
    n, d = privkey
    m = pow(ciphertext, d, n)
    message = long_to_bytes(m)
    return message

def test_rsa():
    pubkey, privkey = generate_rsa_keys()
    message = b"Hello, RSA!"
    ciphertext = rsa_encrypt(message, pubkey)
    decrypted_message = rsa_decrypt(ciphertext, privkey)
    assert message == decrypted_message, "Decryption failed!"
    print("RSA Encryption/Decryption successful. Decrypted message:", decrypted_message)

def mitm_rsa_attack():
    pubkey, privkey = generate_rsa_keys()
    n, e = pubkey

    # Alice
    s = random.randint(1, n-1)
    c = pow(s, e, n)

    # Mallory intercepts and modifies c
    F = lambda x: x * pow(2, e, n) % n
    c_prime = F(c)

    # Bob decrypts c_prime
    s_prime = rsa_decrypt(c_prime, privkey)
    k = sha256(s_prime).digest()[:16]

    message_a = b"Hi Bob!"
    cipher_a = AES.new(k, AES.MODE_CBC)
    iv = cipher_a.iv  # Get the IV used for encryption
    c0 = cipher_a.encrypt(pad(message_a, AES.block_size))

    # Mallory decrypts c0
    cipher_mallory = AES.new(k, AES.MODE_CBC, iv=iv)
    decrypted_a = unpad(cipher_mallory.decrypt(c0), AES.block_size)

    print("MITM RSA Attack successful. Decrypted message:", decrypted_a)

mitm_rsa_attack()
test_rsa()
