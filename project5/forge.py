# 这里是中本聪的内容
import hashlib
import random
from typing import Tuple

# 椭圆曲线参数 (secp256k1 - 比特币使用的曲线)
P = 2**256 - 2**32 - 977  # 素数域
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # 曲线阶
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


class VulnerableECDSA:
    def __init__(self):
        self.p = P
        self.n = N
        self.g = (Gx, Gy)
        self.k = None  # 固定随机数k (安全漏洞!)

    def _mod_inverse(self, a, m):
        """扩展欧几里得算法求模逆"""
        if a == 0:
            return 0
        lm, hm = 1, 0
        low, high = a % m, m
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            lm, low, hm, high = nm, new, lm, low
        return lm % m

    def _point_add(self, p, q):
        """椭圆曲线点加"""
        if p is None:
            return q
        if q is None:
            return p
        xp, yp = p
        xq, yq = q
        if xp == xq and yp != yq:
            return None
        if p == q:
            lam = (3 * xp * xp) * self._mod_inverse(2 * yp, self.p) % self.p
        else:
            lam = (yq - yp) * self._mod_inverse(xq - xp, self.p) % self.p
        xr = (lam * lam - xp - xq) % self.p
        yr = (lam * (xp - xr) - yp) % self.p
        return (xr, yr)

    def _point_mul(self, k, point):
        """标量乘法"""
        result = None
        addend = point
        while k:
            if k & 1:
                result = self._point_add(result, addend)
            addend = self._point_add(addend, addend)
            k >>= 1
        return result

    def generate_keys(self):
        """生成密钥对"""
        private_key = random.randint(1, self.n - 1)
        public_key = self._point_mul(private_key, self.g)
        return private_key, public_key

    def sign(self, message: bytes, private_key: int, fixed_k: int = None) -> Tuple[int, int]:
        """有漏洞的签名实现 (允许固定k值)"""
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big')

        # 安全漏洞：允许固定随机数k
        k = fixed_k if fixed_k else random.randint(1, self.n - 1)
        self.k = k  # 存储k值 (另一个安全漏洞)

        # 计算点 (x, y) = k * G
        point = self._point_mul(k, self.g)
        r = point[0] % self.n
        s = (self._mod_inverse(k, self.n) * (e + private_key * r)) % self.n
        return (r, s)

    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
        """签名验证"""
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        w = self._mod_inverse(s, self.n)
        u1 = (e * w) % self.n
        u2 = (r * w) % self.n

        point = self._point_add(
            self._point_mul(u1, self.g),
            self._point_mul(u2, public_key)
        )
        return point and point[0] % self.n == r


class SignatureForger:
    def __init__(self, target_public_key, curve_n):
        self.target_public_key = target_public_key
        self.n = curve_n  # 曲线阶

    def forge_signature(self, original_message, original_signature, new_message):
        """
        伪造签名步骤：
        1. 获取原始签名(r, s)和对应的消息
        2. 计算两个消息的哈希差
        3. 推导私钥相关参数
        4. 生成新消息的签名
        """
        r, s = original_signature

        # 计算哈希值
        e_orig = int.from_bytes(hashlib.sha256(original_message).digest(), 'big')
        e_new = int.from_bytes(hashlib.sha256(new_message).digest(), 'big')

        # 计算哈希差
        delta_e = (e_new - e_orig) % self.n

        # 推导新签名 (利用固定k漏洞)
        # 关键修复：使用正确的数学公式
        s_new = (s + delta_e * pow(r, -1, self.n)) % self.n

        return (r, s_new)


# 测试演示
if __name__ == "__main__":
    # 初始化脆弱签名系统
    ecdsa = VulnerableECDSA()
    private_key, public_key = ecdsa.generate_keys()

    # 原始消息
    original_msg = b"Satoshi Nakamoto sends 1 BTC to Alice"
    print(f"\n原始消息: {original_msg.decode()}")

    # 使用固定k值签名 (安全漏洞!)
    FIXED_K = 123456789  # 固定随机数k
    signature = ecdsa.sign(original_msg, private_key, fixed_k=FIXED_K)
    print(f"原始签名: r={signature[0]}\n         s={signature[1]}")

    # 验证原始签名
    valid = ecdsa.verify(original_msg, signature, public_key)
    print(f"签名验证: {'成功' if valid else '失败'}")

    # 伪造新消息
    new_msg = b"Satoshi Nakamoto sends 100 BTC to Attacker"
    print(f"\n伪造消息: {new_msg.decode()}")

    # 创建伪造器 (传递曲线阶N)
    forger = SignatureForger(public_key, N)

    # 伪造签名
    forged_signature = forger.forge_signature(original_msg, signature, new_msg)
    print(f"伪造签名: r={forged_signature[0]}\n         s={forged_signature[1]}")

    # 验证伪造签名
    forged_valid = ecdsa.verify(new_msg, forged_signature, public_key)
    print(f"伪造签名验证: {'成功' if forged_valid else '失败'}")