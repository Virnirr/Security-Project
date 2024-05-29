import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def diffie_hellman_real():
    p = int(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
        "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
        "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    g = int(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
        "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
        "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Alice
    a = random.randint(1, p-1)
    A = pow(g, a, p)

    # Bob
    b = random.randint(1, p-1)
    B = pow(g, b, p)

    # Exchange A and B

    # Alice computes the shared secret
    s_a = pow(B, a, p)
    k_a = sha256(s_a.to_bytes(128, 'big')).digest()[:16]

    # Bob computes the shared secret
    s_b = pow(A, b, p)
    k_b = sha256(s_b.to_bytes(128, 'big')).digest()[:16]

    assert k_a == k_b, "Keys do not match!"

    # Encrypt and decrypt a message using AES-CBC
    message_a = input("Enter a message: ").encode()
    cipher_a = AES.new(k_a, AES.MODE_CBC)
    c0 = cipher_a.encrypt(pad(message_a, AES.block_size))

    cipher_b = AES.new(k_b, AES.MODE_CBC, iv=cipher_a.iv)
    decrypted_a = unpad(cipher_b.decrypt(c0), AES.block_size)

    assert message_a == decrypted_a, "Decryption failed!"
    print("Real-life DH Exchange successful. Decrypted message:", decrypted_a)

diffie_hellman_real()
