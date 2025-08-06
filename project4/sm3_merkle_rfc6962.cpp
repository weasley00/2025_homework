#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <array>

using namespace std;
// ====================== SM3 Implementation ======================
static const uint32_t IV_DEFAULT[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

static const uint32_t T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

inline uint32_t ROTL(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline uint32_t P0(uint32_t x) { return x ^ ROTL(x, 9) ^ ROTL(x, 17); }
inline uint32_t P1(uint32_t x) { return x ^ ROTL(x, 15) ^ ROTL(x, 23); }
inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}
inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

std::string to_hex(const std::array<uint32_t, 8>& V) {
    std::ostringstream oss;
    for (size_t i = 0; i < 8; i++) {
        oss << hex << std::setw(8) << setfill('0') << V[i];
    }
    return oss.str();
}

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
    for (int j = 0; j < 64; j++) W_[j] = W[j] ^ W[j + 4];

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

std::string sm3(const string& msg) {
    array<uint32_t, 8> V; memcpy(V.data(), IV_DEFAULT, 32);
    uint64_t bitlen = (uint64_t)msg.size() * 8;
    vector<uint8_t> data(msg.begin(), msg.end());
    data.push_back(0x80);
    while ((data.size() % 64) != 56) data.push_back(0);
    for (int i = 7; i >= 0; i--) data.push_back((uint8_t)(bitlen >> (i * 8)));
    for (size_t i = 0; i < data.size(); i += 64) CF(V, &data[i]);
    return to_hex(V);
}

// ====================== RFC6962 Merkle Tree ======================
std::string LeafHash(const std::string& data) {
    return sm3(std::string(1, '\x00') + data);
}
std::string NodeHash(const string& left, const string& right) {
    return sm3(string(1, '\x01') + left + right);
}

class MerkleTree {
public:
    vector<vector<string>> levels; // levels[0] = leaves
    MerkleTree(const vector<string>& leaves) {
        levels.push_back(leaves);
        build();
    }
    void build() {
        while (levels.back().size() > 1) {
            const vector<string>& prev = levels.back();
            std::vector<std::string> cur;
            for (size_t i = 0; i < prev.size(); i += 2) {
                if (i + 1 < prev.size()) cur.push_back(NodeHash(prev[i], prev[i + 1]));
                else cur.push_back(NodeHash(prev[i], prev[i])); // duplicate last
            }
            levels.push_back(cur);
        }
    }
    std::string root() const { return levels.back()[0]; }
    std::vector<string> getInclusionProof(size_t index) const {
        std::vector<string> proof;
        size_t idx = index;
        for (size_t level = 0; level < levels.size() - 1; level++) {
            size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (sibling < levels[level].size()) proof.push_back(levels[level][sibling]);
            idx /= 2;
        }
        return proof;
    }
    bool verifyInclusion(const string& leafHash, const vector<string>& proof,
        size_t index, const string& root) const {
        std::string computed = leafHash;
        size_t idx = index;
        for (size_t i = 0; i < proof.size(); i++) {
            if (idx % 2 == 0) computed = NodeHash(computed, proof[i]);
            else computed = NodeHash(proof[i], computed);
            idx /= 2;
        }
        return computed == root;
    }
};

// ====================== Main Test ======================
int main() {
    size_t N = 100000; // 100k leaves
    std::vector<string> leaves; leaves.reserve(N);
    for (size_t i = 0; i < N; i++) leaves.push_back(LeafHash("leaf_" + to_string(i)));

    auto start = std::chrono::high_resolution_clock::now();
    MerkleTree tree(leaves);
    auto end = std::chrono::high_resolution_clock::now();

    double build_time = std::chrono::duration<double>(end - start).count();
    std::cout << "[Merkle Tree built] Leaves=" << N
        << " Root=" << tree.root().substr(0, 16) << "...\n";
    std::cout << "Build time=" << build_time << " sec\n";

    // Test Inclusion Proof
    size_t idx = 12345;
    std::vector<std::string> proof = tree.getInclusionProof(idx);
    bool ok = tree.verifyInclusion(leaves[idx], proof, idx, tree.root());
    std::cout << "Verify leaf " << idx << " -> " << (ok ? "SUCCESS" : "FAIL") << "\n";

    return 0;
}
