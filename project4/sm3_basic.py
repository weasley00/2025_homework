import struct

# 常量参数
IV = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E
]

T_j = [0x79CC4519 if j < 16 else 0x7A879D8A for j in range(64)]

# 循环左移
def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# 布尔函数
def FF(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)

def GG(X, Y, Z, j):
    if j < 16:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (~X & Z)

# 置换函数
def P0(X):
    return X ^ left_rotate(X, 9) ^ left_rotate(X, 17)

def P1(X):
    return X ^ left_rotate(X, 15) ^ left_rotate(X, 23)

# 消息填充
def padding(msg):
    msg_len = len(msg)
    bit_len = msg_len * 8
    msg += b'\x80'
    while (len(msg) % 64) != 56:
        msg += b'\x00'
    msg += struct.pack('>Q', bit_len)
    return msg

# 消息扩展
def message_expand(block):
    W = []
    W_ = []
    for i in range(16):
        W.append(struct.unpack('>I', block[i*4:(i+1)*4])[0])
    for j in range(16, 68):
        Wj = P1(W[j-16] ^ W[j-9] ^ left_rotate(W[j-3], 15)) ^ left_rotate(W[j-13], 7) ^ W[j-6]
        W.append(Wj & 0xFFFFFFFF)
    for j in range(64):
        W_.append(W[j] ^ W[j+4])
    return W, W_

# 压缩函数
def CF(V_i, block):
    A, B, C, D, E, F, G, H = V_i
    W, W_ = message_expand(block)

    for j in range(64):
        SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T_j[j], j % 32)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ left_rotate(A, 12)
        TT1 = (FF(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = left_rotate(B, 9)
        B = A
        A = TT1
        H = G
        G = left_rotate(F, 19)
        F = E
        E = P0(TT2)

    V_j = [a ^ b for a, b in zip(V_i, [A, B, C, D, E, F, G, H])]
    return V_j

# SM3 哈希主函数
def sm3_hash(msg: bytes):
    msg = padding(msg)
    n = len(msg) // 64
    V = IV[:]
    for i in range(n):
        block = msg[i*64:(i+1)*64]
        V = CF(V, block)
    return ''.join(['{:08x}'.format(x) for x in V])

# 测试
if __name__ == '__main__':
    test_msg = b"abc"
    print("消息：", test_msg)
    print("SM3 哈希值：", sm3_hash(test_msg))
