# project 1
## task
1、实现sm4基本加解密。<br>
2、从以下几个方面进行优化: T-table优化，AES-NI类似指令集优化，最近SIMD指令集<br>
3、SM4-GCM模式实现及优化
## 一、SM4基本实现
### 基本参数
分组长度： 128位（16字节）。每次处理一个128位的明文/密文分组。<br>
密钥长度： 128位（16字节）。<br>
结构： 非平衡Feistel网络。与DES类似，但轮函数作用于整个128位状态的左半部分（64位），然后与右半部分进行异或。<br>
轮数： 32轮。经过32轮相同的迭代操作（轮函数）进行加密或解密。<br>
安全性： 设计目标提供128位的安全强度。至今未发现有效的实际攻击（如线性攻击、差分攻击等能显著降低其安全强度）。<br>
### 加密过程
输入：<br>
明文分组 P (128位)<br>
加密密钥 MK (128位)<br>
密钥扩展： 使用 MK 生成 32个轮密钥 (rk₀, rk₁, ..., rk₃₁) (每个32位)。这是算法的关键预处理步骤。<br>
初始变换：<br>
将128位明文 P 拆分成4个32位字：P = (X₀, X₁, X₂, X₃)<br>
执行一个初始异或操作（使用系统参数 FK）：<br>
(X₀, X₁, X₂, X₃) = (X₀ ⊕ FK₀, X₁ ⊕ FK₁, X₂ ⊕ FK₂, X₃ ⊕ FK₃)<br>
FK₀ = 0xA3B1BAC6<br>
FK₁ = 0x56AA3350<br>
FK₂ = 0x677D9197<br>
FK₃ = 0xB27022DC<br>
32轮迭代：<br>
对于每一轮 i = 0 到 31：<br>
X_{i+4} = X_i ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rk_i)<br>
其中 T(·) 是一个可逆合成变换（核心非线性部分），由两个子变换组成：T(·) = L(τ(·))<br>
τ(·)：非线性字节替换（S盒）。将输入的32位字拆分成4个字节，每个字节独立地通过一个固定的8位输入8位输出的S盒进行替换。SM4的S盒设计基于有限域上的仿射变换，具有良好的非线性特性和差分均匀性，是算法安全的关键。S盒的具体值在标准中定义。<br>
L(·)：线性扩散变换。对τ(·)输出的32位字进行一个线性变换，提供扩散性。定义为：<br>
L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)（<<< 表示循环左移）<br>
rk_i：第 i 轮的轮密钥（32位）。<br>
反序变换：<br>
经过32轮迭代后，得到 (X₃₂, X₃₃, X₃₄, X₃₅)<br>
对输出顺序进行反转：<br>
(Y₀, Y₁, Y₂, Y₃) = (X₃₅, X₃₄, X₃₃, X₃₂)<br>
输出： 将 (Y₀, Y₁, Y₂, Y₃) 拼接成128位密文分组 C。<br>
### 解密过程
由于使用了feistel结构，所以解密和加密使用的是完全相同的结构，唯一的区别是轮密钥的使用顺序相反。
<img width="1112" height="621" alt="image" src="https://github.com/user-attachments/assets/b4c6aa63-814a-46b9-9722-af5057bda081" />
## 二、T-Table优化
SM4每轮运算中，核心操作是<br>
X[i+4] = X[i] ^ L(S(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]))<br>
其中。S() 是字节级替换（S-box），L() 是线性变换，包含 5次循环左移和 XOR。<br>
在基础实现中，每轮需要：4次S-box，4次32-bit组合，4次ROL和XOR。<br>
所以，优化思路为，将S-box和L()合并为查表操作，用 4个查表表（T0,T1,T2,T3）处理32-bit值的4个字节：T(x) = T0[a0] ^ T1[a1] ^ T2[a2] ^ T3[a3]。<br>
这样，SM4 每轮只需4次查表+3次XOR，大幅减少运算量。<br>
```c
void sm4_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16)
             | ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    }
    for (int i = 0; i < 32; i++) {
        X[i+4] = X[i] ^ T_opt(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]);
    }
    for (int i = 0; i < 4; i++) {
        out[4*i]   = (X[35 - i] >> 24) & 0xFF;
        out[4*i+1] = (X[35 - i] >> 16) & 0xFF;
        out[4*i+2] = (X[35 - i] >> 8) & 0xFF;
        out[4*i+3] = X[35 - i] & 0xFF;
    }
}
```
## 三、AVX2优化
AVX2 是英特尔在 2013 年推出的 第二代高级向量扩展指令集，作为初代 AVX（2011 年）的增强版本。它延续了256位SIMD架构，通过指令集扩展和寄存器操作优化，显著提升了并行计算能力，广泛应用于主流 CPU 平台。
```c
void sm4_encrypt4_avx2(const uint8_t in[4][16], uint8_t out[4][16], const uint32_t rk[32]) {
    // 按列处理，每个__m256i包含4块相同位置的字
    __m256i X0, X1, X2, X3;

    // Load输入
    uint32_t tmp[16];
    for (int i = 0; i < 4; i++) {
        memcpy(&tmp[i*4], in[i], 16);
    }
    X0 = _mm256_set_epi32(tmp[12], tmp[8], tmp[4], tmp[0],
                          tmp[12], tmp[8], tmp[4], tmp[0]);
    X1 = _mm256_set_epi32(tmp[13], tmp[9], tmp[5], tmp[1],
                          tmp[13], tmp[9], tmp[5], tmp[1]);
    X2 = _mm256_set_epi32(tmp[14], tmp[10], tmp[6], tmp[2],
                          tmp[14], tmp[10], tmp[6], tmp[2]);
    X3 = _mm256_set_epi32(tmp[15], tmp[11], tmp[7], tmp[3],
                          tmp[15], tmp[11], tmp[7], tmp[3]);

    for (int i = 0; i < 32; i++) {
        __m256i rkvec = _mm256_set1_epi32(rk[i]);
        __m256i tmpx = _mm256_xor_si256(_mm256_xor_si256(X1, X2), X3);
        tmpx = _mm256_xor_si256(tmpx, rkvec);
        tmpx = _mm256_xor_si256(X0, T_avx2(tmpx));
        X0 = X1;
        X1 = X2;
        X2 = X3;
        X3 = tmpx;
    }
```

## 四、AVX512优化
AVX512 是英特尔开发的一套 高级向量扩展指令集，属于 SIMD（单指令多数据流）技术。它是前代 AVX 和 AVX2（256位宽度）的扩展，核心特点是寄存器宽度提升至512位，可并行处理更多数据，大幅提升CPU在特定计算任务中的性能。
```c
void sm4_encrypt8_avx512(const uint8_t in[8][16], uint8_t out[8][16], const uint32_t rk[32]) {
    __m512i X0, X1, X2, X3;
    alignas(64) uint32_t tmp[32];
    for (int i = 0; i < 8; i++) memcpy(&tmp[i*4], in[i], 16);

    // 按列装载
    X0 = _mm512_set_epi32(tmp[28],tmp[24],tmp[20],tmp[16],tmp[12],tmp[8],tmp[4],tmp[0],
                          tmp[28],tmp[24],tmp[20],tmp[16],tmp[12],tmp[8],tmp[4],tmp[0]);
    X1 = _mm512_set_epi32(tmp[29],tmp[25],tmp[21],tmp[17],tmp[13],tmp[9],tmp[5],tmp[1],
                          tmp[29],tmp[25],tmp[21],tmp[17],tmp[13],tmp[9],tmp[5],tmp[1]);
    X2 = _mm512_set_epi32(tmp[30],tmp[26],tmp[22],tmp[18],tmp[14],tmp[10],tmp[6],tmp[2],
                          tmp[30],tmp[26],tmp[22],tmp[18],tmp[14],tmp[10],tmp[6],tmp[2]);
    X3 = _mm512_set_epi32(tmp[31],tmp[27],tmp[23],tmp[19],tmp[15],tmp[11],tmp[7],tmp[3],
                          tmp[31],tmp[27],tmp[23],tmp[19],tmp[15],tmp[11],tmp[7],tmp[3]);

    for (int i = 0; i < 32; i++) {
        __m512i rkvec = _mm512_set1_epi32(rk[i]);
        __m512i tmpx = _mm512_xor_si512(_mm512_xor_si512(X1, X2), X3);
        tmpx = _mm512_xor_si512(tmpx, rkvec);
        tmpx = _mm512_xor_si512(X0, T_avx512(tmpx));
        X0 = X1;
        X1 = X2;
        X2 = X3;
        X3 = tmpx;
    }
```
## 五、SM4-GCM 优化
GCM = CTR + GHASH<br>
CTR部分：<br>
用 SM4 加密计数器并 XOR plaintext<br>
可并行 N 个 block（4块 AVX2，8块 AVX512）<br>
GHASH部分：<br>
用 PCLMULQDQ 做 GF(2^128) 乘法<br>
可以处理多个 block 累加<br>
```c
static void ghash_pclmul(__m128i *acc, const __m128i *h, const __m128i *x) {
    __m128i a = *acc;
    __m128i b = *x;
    __m128i h1 = *h;

    __m128i t1 = _mm_clmulepi64_si128(a, h1, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(a, h1, 0x11);
    __m128i t3 = _mm_xor_si128(_mm_clmulepi64_si128(a, h1, 0x10),
                               _mm_clmulepi64_si128(a, h1, 0x01));

    __m128i t4 = _mm_xor_si128(t1, _mm_slli_si128(t3, 8));
    __m128i t5 = _mm_xor_si128(t2, _mm_srli_si128(t3, 8));

    // 简化：未完全做mod归约，正式实现需GF(2^128)归约
    *acc = _mm_xor_si128(t4, t5);
}
void sm4_gcm_encrypt(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[16], const uint8_t iv[12], uint8_t tag[16]) {
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    size_t blocks = len / 16;
    sm4_ctr_avx2(out, in, blocks, iv, rk);

    // GHASH 初始化
    __m128i acc = _mm_setzero_si128();
    __m128i H = _mm_setzero_si128(); // 通常由 E(K,0) 生成
    for (size_t i = 0; i < blocks; i++) {
        __m128i x = _mm_loadu_si128((__m128i*)(out + i*16));
        acc = _mm_xor_si128(acc, x);
        ghash_pclmul(&acc, &H, &x);
    }
    _mm_storeu_si128((__m128i*)tag, acc);
}
```


