#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <cstdint>

using namespace std;
// SM3 常量
static const uint32_t IV_DEFAULT[8] = {
    0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
    0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
};

static const uint32_t T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

// 辅助函数
inline uint32_t ROTL(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
inline uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }

inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

string to_hex(const std::array<uint32_t, 8>& V) {
    ostringstream oss;
    for (auto v : V) {
        oss << hex << setw(8) << setfill('0') << v;
    }
    return oss.str();
}

// 压缩函数
void CF(array<uint32_t, 8>& V, const uint8_t block[64]) {
    uint32_t W[68], W_[64];
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[4 * i] << 24) |
            ((uint32_t)block[4 * i + 1] << 16) |
            ((uint32_t)block[4 * i + 2] << 8) |
            ((uint32_t)block[4 * i + 3]);
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W_[j] = W[j] ^ W[j + 4];
    }

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j % 32)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W_[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// 填充函数
vector<uint8_t> pad_message(const string& msg, uint64_t total_len_bits) {
    std::vector<uint8_t> res(msg.begin(), msg.end());
    res.push_back(0x80);
    while ((res.size() % 64) != 56) res.push_back(0);
    for (int i = 7; i >= 0; i--) {
        res.push_back((uint8_t)(total_len_bits >> (i * 8)));
    }
    return res;
}

// 正常 SM3
string sm3(const string& msg) {
    array<uint32_t, 8> V;
    memcpy(V.data(), IV_DEFAULT, 32);
    auto padded = pad_message(msg, msg.size() * 8);
    for (size_t i = 0; i < padded.size(); i += 64) {
        CF(V, &padded[i]);
    }
    return to_hex(V);
}

// 长度扩展攻击：继续哈希 extra
string sm3_continue(const array<uint32_t, 8>& prev_V, const string& extra, uint64_t total_len_bits) {
    array<uint32_t, 8> V = prev_V;
    auto padded = pad_message(extra, total_len_bits);
    for (size_t i = 0; i < padded.size(); i += 64) {
        CF(V, &padded[i]);
    }
    return to_hex(V);
}

int main() {
    // 原始消息
    string original = "abc";
    string extra = "123456";

    cout << "[原始消息] " << original << std::endl;
    string original_hash = sm3(original);
    cout << "[SM3(original)] " << original_hash << std::endl;

    // 模拟攻击
    // 假设攻击者知道 original_hash 和 len(original)
    array<uint32_t, 8> iv;
    for (int i = 0; i < 8; i++) {
        iv[i] = std::stoul(original_hash.substr(i * 8, 8), nullptr, 16);
    }

    // 计算 total_len: original + padding + extra
    uint64_t fake_total_len = (original.size() + pad_message(original, original.size() * 8).size() - original.size() + extra.size()) * 8;
    string forged_hash = sm3_continue(iv, extra, fake_total_len);
    cout << "[攻击者伪造的 hash] " << forged_hash << std::endl;

    // 验证真实 hash
    string full_message = original + std::string((char*)pad_message(original, original.size() * 8).data() + original.size(),
        pad_message(original, original.size() * 8).size() - original.size()) + extra;
    string real_hash = sm3(full_message);
    cout << "[真实 SM3(original||padding||extra)] " << real_hash << endl;

    cout << "\n[结果] " << (real_hash == forged_hash ? "攻击成功" : "攻击失败") << endl;

    return 0;
}
