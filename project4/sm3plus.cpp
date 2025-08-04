#include <immintrin.h>
#include <iostream>
#include <vector>
#include <thread>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <algorithm>

#define BLOCK_SIZE 64
#define HASH_SIZE 32
#define SIMD_WIDTH 8  // AVX2: 256-bit, 8 × 32-bit

// SM3 初始向量
const uint32_t IV[8] = {
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E
};

// T_j 常量
const uint32_t T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

// SIMD 辅助函数
inline __m256i ROTL32(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

inline __m256i P0(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x, 9)), ROTL32(x, 17));
}

inline __m256i P1(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, ROTL32(x, 15)), ROTL32(x, 23));
}

inline __m256i FF(__m256i X, __m256i Y, __m256i Z, int j) {
    return (j < 16) ? _mm256_xor_si256(_mm256_xor_si256(X, Y), Z)
        : _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(X, Y), _mm256_and_si256(X, Z)), _mm256_and_si256(Y, Z));
}

inline __m256i GG(__m256i X, __m256i Y, __m256i Z, int j) {
    return (j < 16) ? _mm256_xor_si256(_mm256_xor_si256(X, Y), Z)
        : _mm256_or_si256(_mm256_and_si256(X, Y), _mm256_and_si256(_mm256_andnot_si256(X, _mm256_set1_epi32(-1)), Z));
}

// SIMD 压缩函数：处理 8 条消息
void SM3_Compress_SIMD(uint8_t blocks[SIMD_WIDTH][BLOCK_SIZE], uint32_t digest[SIMD_WIDTH][8]) {
    __m256i A = _mm256_set1_epi32(IV[0]);
    __m256i B = _mm256_set1_epi32(IV[1]);
    __m256i C = _mm256_set1_epi32(IV[2]);
    __m256i D = _mm256_set1_epi32(IV[3]);
    __m256i E = _mm256_set1_epi32(IV[4]);
    __m256i F = _mm256_set1_epi32(IV[5]);
    __m256i G = _mm256_set1_epi32(IV[6]);
    __m256i H = _mm256_set1_epi32(IV[7]);

    __m256i W[68], W_[64];

    // 消息扩展
    for (int i = 0; i < 16; i++) {
        uint32_t tmp[SIMD_WIDTH];
        for (int j = 0; j < SIMD_WIDTH; j++) {
            tmp[j] = ((uint32_t)blocks[j][4 * i] << 24) |
                ((uint32_t)blocks[j][4 * i + 1] << 16) |
                ((uint32_t)blocks[j][4 * i + 2] << 8) |
                ((uint32_t)blocks[j][4 * i + 3]);
        }
        W[i] = _mm256_loadu_si256((__m256i*)tmp);
    }
    for (int j = 16; j < 68; j++) {
        W[j] = _mm256_xor_si256(P1(_mm256_xor_si256(_mm256_xor_si256(W[j - 16], W[j - 9]), ROTL32(W[j - 3], 15))),
            _mm256_xor_si256(ROTL32(W[j - 13], 7), W[j - 6]));
    }
    for (int j = 0; j < 64; j++) {
        W_[j] = _mm256_xor_si256(W[j], W[j + 4]);
    }

    // 压缩
    for (int j = 0; j < 64; j++) {
        __m256i Tj = _mm256_set1_epi32(T[j]);
        __m256i SS1 = ROTL32(_mm256_add_epi32(_mm256_add_epi32(ROTL32(A, 12), E), ROTL32(Tj, j % 32)), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, ROTL32(A, 12));
        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF(A, B, C, j), D), SS2), W_[j]);
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG(E, F, G, j), H), SS1), W[j]);

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 保存结果
    uint32_t buf[8][SIMD_WIDTH];
    _mm256_storeu_si256((__m256i*)buf[0], A);
    _mm256_storeu_si256((__m256i*)buf[1], B);
    _mm256_storeu_si256((__m256i*)buf[2], C);
    _mm256_storeu_si256((__m256i*)buf[3], D);
    _mm256_storeu_si256((__m256i*)buf[4], E);
    _mm256_storeu_si256((__m256i*)buf[5], F);
    _mm256_storeu_si256((__m256i*)buf[6], G);
    _mm256_storeu_si256((__m256i*)buf[7], H);

    for (int i = 0; i < SIMD_WIDTH; i++) {
        for (int j = 0; j < 8; j++) {
            digest[i][j] = buf[j][i] ^ IV[j];
        }
    }
}

// 多线程批量处理
void SM3_Hash_MultiThread(const std::vector<std::vector<uint8_t>>& messages, int threads) {
    int batch = SIMD_WIDTH;
    int total = messages.size();
    int per_thread = (total + threads - 1) / threads;

    auto worker = [&](int start, int end) {
        uint8_t blocks[SIMD_WIDTH][BLOCK_SIZE];
        uint32_t digest[SIMD_WIDTH][8];

        for (int i = start; i < end; i += batch) {
            int n = std::min(batch, end - i);
            for (int j = 0; j < n; j++) {
                memcpy(blocks[j], messages[i + j].data(), BLOCK_SIZE);
            }
            SM3_Compress_SIMD(blocks, digest);
        }
    };

    std::vector<std::thread> pool;
    for (int t = 0; t < threads; t++) {
        int start = t * per_thread;
        int end = std::min(start + per_thread, total);
        if (start < end)
            pool.emplace_back(worker, start, end);
    }
    for (auto& th : pool) th.join();
}

// 生成填充好的消息（单块）
std::vector<uint8_t> GenerateMessage(size_t len) {
    std::vector<uint8_t> msg(BLOCK_SIZE, 0);
    for (size_t i = 0; i < len; i++) msg[i] = 'a';
    msg[len] = 0x80;
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++) {
        msg[BLOCK_SIZE - 1 - i] = (uint8_t)(bit_len >> (i * 8));
    }
    return msg;
}

int main() {
    int threads = std::thread::hardware_concurrency();
    int batch_size = 8000;
    size_t msg_len = 32;

    std::vector<std::vector<uint8_t>> messages(batch_size, GenerateMessage(msg_len));

    auto start = std::chrono::high_resolution_clock::now();
    SM3_Hash_MultiThread(messages, threads);
    auto end = std::chrono::high_resolution_clock::now();

    double seconds = std::chrono::duration<double>(end - start).count();
    double throughput = (batch_size * msg_len) / (1024.0 * 1024.0) / seconds;

    std::cout << "批量: " << batch_size << ", 每条: " << msg_len << " 字节\n";
    std::cout << "线程数: " << threads << ", 耗时: " << seconds << " s\n";
    std::cout << "吞吐: " << std::fixed << std::setprecision(2) << throughput << " MB/s\n";

    return 0;
}
