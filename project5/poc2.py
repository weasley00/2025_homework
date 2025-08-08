# 签名误用
import hashlib

# simulate SM2 style signing
def sm2_sign(hash_data: bytes, private_key: int):
    # simplified signature: just dummy r = H + d
    e = int.from_bytes(hash_data, 'big')
    r = (e + private_key) % 0xFFFFFFF
    s = (e * private_key + 12345) % 0xFFFFFFF
    return (r, s)

def sm2_verify(hash_data: bytes, sig, public_key: int):
    e = int.from_bytes(hash_data, 'big')
    r, s = sig
    return (r - e) % 0xFFFFFFF == public_key

# Attacker known message and hash
orig_msg = b"Transfer 1 BTC to Alice"
fake_msg = b"Transfer 10000 BTC to Mallory"

# vulnerable system: signs on Hash(M)
hash_orig = hashlib.sha256(orig_msg).digest()
hash_fake = hashlib.sha256(fake_msg).digest()

# attacker finds fake message with same hash (in real attack: collision or length extension)
# For demo, we override hash_fake = hash_orig
hash_fake = hash_orig

# keypair
sk = 12345678
pk = sk  # assume same (simplified)

# attacker obtains valid signature for original message
sig = sm2_sign(hash_orig, sk)

# attacker sends fake message with same hash and valid signature
verify_orig = sm2_verify(hash_orig, sig, pk)
verify_fake = sm2_verify(hash_fake, sig, pk)

print("[*] Signature from original:", sig)
print("[*] Verify original msg:", verify_orig)
print("[*] Verify fake    msg:", verify_fake)
