#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

// =========================
// ����
// =========================
#define SM4_BLOCK_SIZE 16
#define MAX_BLOCKS 1000000

// =========================
// SM4 ����
// =========================
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

static const uint8_t SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// =========================
// ��������
// =========================
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t tau(uint32_t a) {
    return (SBOX[(a >> 24) & 0xFF] << 24) |
        (SBOX[(a >> 16) & 0xFF] << 16) |
        (SBOX[(a >> 8) & 0xFF] << 8) |
        (SBOX[a & 0xFF]);
}

static inline uint32_t L(uint32_t b) {
    return b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24);
}

static inline uint32_t T(uint32_t x) {
    return L(tau(x));
}

// =========================
// SM4 Key Schedule
// =========================
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    static const uint32_t FK[4] = { 0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc };
    uint32_t MK[4];
    for (int i = 0; i < 4; i++) {
        MK[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) | ((uint32_t)key[4 * i + 3]);
    }
    uint32_t K[36];
    for (int i = 0; i < 4; i++) K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = tau(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
        tmp = tmp ^ rotl32(tmp, 13) ^ rotl32(tmp, 23);
        K[i + 4] = K[i] ^ tmp;
        rk[i] = K[i + 4];
    }
}

// =========================
// ���������
// =========================
void sm4_encrypt_base(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) | ((uint32_t)in[4 * i + 3]);
    }
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    for (int i = 0; i < 4; i++) {
        uint32_t v = X[35 - i];
        out[4 * i] = v >> 24; out[4 * i + 1] = v >> 16; out[4 * i + 2] = v >> 8; out[4 * i + 3] = v;
    }
}

// =========================
// ���ܼ�ʱ
// =========================
double now() {
    using namespace std::chrono;
    return duration<double>(high_resolution_clock::now().time_since_epoch()).count();
}

// =========================
// T-Table �Ż�
// =========================
static uint32_t TBOX[4][256];

void sm4_init_ttable() {
    for (int i = 0; i < 256; i++) {
        uint32_t t = tau(i << 24);
        uint32_t L_val = t ^ rotl32(t, 2) ^ rotl32(t, 10) ^ rotl32(t, 18) ^ rotl32(t, 24);
        TBOX[0][i] = L_val;
        TBOX[1][i] = rotl32(L_val, 8);
        TBOX[2][i] = rotl32(L_val, 16);
        TBOX[3][i] = rotl32(L_val, 24);
    }
}

inline uint32_t T_fast(uint32_t x) {
    return TBOX[0][(x >> 24) & 0xFF] ^
        TBOX[1][(x >> 16) & 0xFF] ^
        TBOX[2][(x >> 8) & 0xFF] ^
        TBOX[3][x & 0xFF];
}

void sm4_encrypt_ttable(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16) |
            ((uint32_t)in[4 * i + 2] << 8) | ((uint32_t)in[4 * i + 3]);
    }
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ T_fast(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    for (int i = 0; i < 4; i++) {
        uint32_t v = X[35 - i];
        out[4 * i] = v >> 24; out[4 * i + 1] = v >> 16; out[4 * i + 2] = v >> 8; out[4 * i + 3] = v;
    }
}

// =========================
// AVX2 ���м��� (4 blocks)
// =========================
void sm4_encrypt4_avx2(const uint8_t in[64], uint8_t out[64], const uint32_t rk[32]) {
    __m256i X0 = _mm256_set_epi32(
        ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3],
        ((uint32_t)in[16] << 24) | ((uint32_t)in[17] << 16) | ((uint32_t)in[18] << 8) | in[19],
        ((uint32_t)in[32] << 24) | ((uint32_t)in[33] << 16) | ((uint32_t)in[34] << 8) | in[35],
        ((uint32_t)in[48] << 24) | ((uint32_t)in[49] << 16) | ((uint32_t)in[50] << 8) | in[51],
        0, 0, 0, 0);

}



// =========================
// CTR ģʽ
// =========================
void sm4_ctr_encrypt(uint8_t* out, const uint8_t* in, size_t blocks,
    const uint32_t rk[32], uint8_t iv[16]) {
    uint8_t counter[16];
    memcpy(counter, iv, 16);
    for (size_t i = 0; i < blocks; i++) {
        uint8_t keystream[16];
        sm4_encrypt_ttable(counter, keystream, rk);
        for (int j = 0; j < 16; j++) {
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];
        }
        for (int k = 15; k >= 0; k--) {
            if (++counter[k]) break;
        }
    }
}

// =========================
// GHASH (PCLMUL)
// =========================
#include <wmmintrin.h>

static inline __m128i ghash_mul(__m128i X, __m128i Y) {
    return _mm_clmulepi64_si128(X, Y, 0x00); 
}

void sm4_gcm_encrypt(uint8_t* out, const uint8_t* in, size_t blocks,
    const uint32_t rk[32], uint8_t iv[16]) {
    uint8_t Hblock[16] = { 0 };
    sm4_encrypt_ttable(Hblock, Hblock, rk);
    __m128i H = _mm_loadu_si128((__m128i*)Hblock);
    __m128i tag = _mm_setzero_si128();

    uint8_t counter[16];
    memcpy(counter, iv, 16);
    for (size_t i = 0; i < blocks; i++) {
        uint8_t keystream[16];
        sm4_encrypt_ttable(counter, keystream, rk);
        for (int j = 0; j < 16; j++) {
            out[i * 16 + j] = in[i * 16 + j] ^ keystream[j];
        }
        __m128i block = _mm_loadu_si128((__m128i*)(out + i * 16));
        tag = _mm_xor_si128(tag, block);
        tag = ghash_mul(tag, H);

        for (int k = 15; k >= 0; k--) {
            if (++counter[k]) break;
        }
    }
}

// =========================
// ���ܲ���������
// =========================
int main(int argc, char* argv[]) {
    sm4_init_ttable();
    uint8_t key[16] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    size_t blocks = 100000; // Ĭ�Ͽ���
    if (argc >= 3) blocks = std::stoul(argv[2]);

    std::string mode = (argc >= 2) ? argv[1] : "all";

    std::vector<uint8_t> in(blocks * 16, 0x11);
    std::vector<uint8_t> out(blocks * 16);

    auto bench = [&](auto func, const char* name) {
        auto start = std::chrono::high_resolution_clock::now();
        func();
        auto end = std::chrono::high_resolution_clock::now();
        double sec = std::chrono::duration<double>(end - start).count();
        double mbps = (blocks * 16.0 / sec) / 1024 / 1024;
        printf("%-10s | %-10zu | %.2f MB/s\n", name, blocks, mbps);
    };

    printf("========================================\n");
    printf("Mode       | Blocks     | Speed(MB/s)\n");
    printf("----------------------------------------\n");

    if (mode == "base" || mode == "all") {
        bench([&] { for (size_t i = 0; i < blocks; i++) sm4_encrypt_base(&in[i * 16], &out[i * 16], rk); }, "Base");
    }
    if (mode == "ttable" || mode == "all") {
        bench([&] { for (size_t i = 0; i < blocks; i++) sm4_encrypt_ttable(&in[i * 16], &out[i * 16], rk); }, "T-Table");
    }
    if (mode == "gcm" || mode == "all") {
        uint8_t iv[16] = { 0 };
        bench([&] { sm4_gcm_encrypt(out.data(), in.data(), blocks, rk, iv); }, "GCM");
    }

    printf("========================================\n");
    return 0;
}

