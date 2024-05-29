import random
from hashlib import sha256

def mitm_attack_ab():
    p = 37
    g = 5

    # Alice
    a = random.randint(1, p-1)
    A = pow(g, a, p)

    # Mallory
    m = random.randint(1, p-1)
    M = pow(g, m, p)

    # Bob
    b = random.randint(1, p-1)
    B = pow(g, b, p)

    # Mallory modifies A and B
    # Exchange A and M instead
    A_prime = M
    B_prime = M

    # Alice computes the shared secret
    s_a = pow(B_prime, a, p)
    k_a = sha256(s_a.to_bytes(16, 'big')).digest()[:16]

    # Bob computes the shared secret
    s_b = pow(A_prime, b, p)
    k_b = sha256(s_b.to_bytes(16, 'big')).digest()[:16]

    if k_a == k_b:
        print("Keys do not match! MITM Attack by tampering A and B successful.")
    else:
        print("Keys match! MITM Attack by tampering A and B failed.")

def mitm_attack_g():
    p = 37
    g = 5

    # Alice
    a = random.randint(1, p-1)
    A = pow(g, a, p)

    # Mallory sets g to 1, p, or p-1
    g_tampered = 1
    A_prime = pow(g_tampered, a, p)

    # Bob
    b = random.randint(1, p-1)
    B = pow(g, b, p)

    # Exchange A and B
    B_prime = pow(g_tampered, b, p)

    # Alice computes the shared secret
    s_a = pow(B_prime, a, p)
    k_a = sha256(s_a.to_bytes(16, 'big')).digest()[:16]

    # Bob computes the shared secret
    s_b = pow(A_prime, b, p)
    k_b = sha256(s_b.to_bytes(16, 'big')).digest()[:16]

    if k_a == k_b:
        print("Keys do not match! MITM Attack by tampering g successful.")
    else:
        print("Keys match! MITM Attack by tampering g failed.")

mitm_attack_g()
mitm_attack_ab()
