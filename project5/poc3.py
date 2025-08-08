# Proof-of-Storage（PoS）结构签名伪造攻击
import hashlib

# Signer side
def sign_data(data: bytes, sk: int):
    h = hashlib.sha256(data).digest()
    e = int.from_bytes(h, 'big')
    r = (e + sk) % 0xFFFFFFF
    s = (e * sk + 12345) % 0xFFFFFFF
    return (r, s)

# Verifier side
def verify_data(data: bytes, sig, pk: int):
    h = hashlib.sha256(data).digest()
    e = int.from_bytes(h, 'big')
    r, s = sig
    return (r - e) % 0xFFFFFFF == pk

# Original data
M = b"Original File Content"
challenge = b"RANDOM_CHALLENGE"
combined = M + challenge

# key pair
sk = 99887766
pk = sk

# Legitimate signature
sig = sign_data(combined, sk)

# ==================== Attack begins ====================

# Assume attacker knows Hash(M)
# Here: attacker guesses/knows M, but wants to respond to other challenge without M

# Attacker creates M', C' such that M' || C' = M || challenge
M_prime = b"Original File"  # partial content only
C_prime = b" ContentRANDOM_CHALLENGE"  # reconstruct to align full message

# Now forge message
forged_combined = M_prime + C_prime

# Server accepts if same signature passes
valid = verify_data(forged_combined, sig, pk)

print("[*] Forged message:", forged_combined)
print("[*] Forged Signature Valid:", valid)
