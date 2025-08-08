# 这里是ppt中的长度拓展攻击

from gmssl import sm3, func

# victim message and secret
secret = b"secret_key"
message = b"original_data"

# attacker knows only Hash(secret || message)
full_msg = secret + message
known_hash = sm3.sm3_hash(func.bytes_to_list(full_msg))

# attacker appends data
append_data = b";admin=true"


# simulate length extension attack
def forge_padding(msg_len):
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    bit_len = (msg_len * 8).to_bytes(8, 'big')
    return pad + bit_len


def sm3_with_iv(msg, iv_hex):
    iv = [int(iv_hex[i:i + 8], 16) for i in range(0, 64, 8)]
    return sm3.sm3_hash(func.bytes_to_list(msg), iv)


# attacker crafts full forged message and hash
forged_padding = forge_padding(len(secret + message))
forged_msg = message + forged_padding + append_data
forged_hash = sm3_with_iv(append_data, known_hash)

print("Forged Hash:", forged_hash)
print("Forged Message Bytes:", forged_msg)
