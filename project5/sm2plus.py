import random
import hashlib
from concurrent.futures import ThreadPoolExecutor

# SM2 recommended curve parameters
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5AEF7E8B5D50A0C648FEE9A97A7E37BBA2DDF1D5
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (Gx, Gy)

# Modular inverse using Fermat's little theorem
def mod_inv(x, m):
    return pow(x, m - 2, m)

# Point addition (optimized)
def point_add(P, Q):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return (0, 0)

    if P == Q:
        l = (3 * P[0] * P[0] + a) * mod_inv(2 * P[1], p) % p
    else:
        l = (Q[1] - P[1]) * mod_inv(Q[0] - P[0], p) % p

    x_r = (l * l - P[0] - Q[0]) % p
    y_r = (l * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

# Scalar multiplication (binary method)
def scalar_mult(k, P):
    R = (0, 0)
    while k > 0:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R

# Key generation
def gen_keypair():
    d = random.randrange(1, n)
    P = scalar_mult(d, G)
    return d, P

# SM2 signature
def sm2_sign(msg, d):
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    while True:
        k = random.randrange(1, n)
        x1, _ = scalar_mult(k, G)
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        if s != 0:
            return (r, s)

# SM2 verification
def sm2_verify(msg, sig, P):
    r, s = sig
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % n
    t = (r + s) % n
    if t == 0:
        return False
    P1 = scalar_mult(s, G)
    P2 = scalar_mult(t, P)
    x1, _ = point_add(P1, P2)
    R = (e + x1) % n
    return R == r

# Parallel signature generation
def batch_sign(msg_list, d, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda m: sm2_sign(m, d), msg_list))
    return results

# Parallel verification
def batch_verify(msg_list, sig_list, P, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda args: sm2_verify(*args), zip(msg_list, sig_list, [P]*len(msg_list))))
    return results

# Performance test
if __name__ == "__main__":
    import time

    d, P = gen_keypair()
    messages = [b"Message #%d" % i for i in range(100)]

    print("Benchmarking 100 signatures and verifications with 4 threads...")

    t1 = time.time()
    sigs = batch_sign(messages, d, max_workers=4)
    t2 = time.time()
    print("Sign time: %.3f sec" % (t2 - t1))

    t3 = time.time()
    results = batch_verify(messages, sigs, P, max_workers=4)
    t4 = time.time()
    print("Verify time: %.3f sec" % (t4 - t3))

    print("All verified:", all(results))
