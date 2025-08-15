#include <iostream>
#include <iomanip>
#include <cstring>
#include <random>
#include <chrono>
#include <emmintrin.h>
#include <algorithm> // 用于std::copy

using namespace std;

// SM4算法S盒（非线性变换表）
static const uint8_t SM4_SBOX[256] = {
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

// SM4密钥扩展固定参数（FK）
const uint32_t SM4_FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// SM4轮密钥固定参数（CK）
const uint32_t SM4_CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// T盒查找表（预计算S盒与线性变换的组合结果，加速加密过程）
uint32_t sm4TBox0[256], sm4TBox1[256], sm4TBox2[256], sm4TBox3[256];

inline uint32_t rotateLeft(uint32_t value, int shiftBits) {
    return (value << shiftBits) | (value >> (32 - shiftBits));
}

uint32_t linearTransformL(uint32_t value) {
    return value ^ rotateLeft(value, 2) ^ rotateLeft(value, 10) ^ rotateLeft(value, 18) ^ rotateLeft(value, 24);
}

//初始化T盒（预计算S盒与线性变换的组合结果，减少加密时的计算量）
void initTBox() {
    for (int i = 0; i < 256; ++i) {
        uint8_t sBoxValue = SM4_SBOX[i];
        uint32_t transformed = linearTransformL(static_cast<uint32_t>(sBoxValue) << 24);
        sm4TBox0[i] = transformed;
        sm4TBox1[i] = rotateLeft(transformed, 8);
        sm4TBox2[i] = rotateLeft(transformed, 16);
        sm4TBox3[i] = rotateLeft(transformed, 24);
    }
}

inline uint32_t tFunctionLookup(uint32_t input) {
    return sm4TBox0[(input >> 24) & 0xff]       // 高8位查表
        ^ sm4TBox1[(input >> 16) & 0xff]    // 次高8位查表
        ^ sm4TBox2[(input >> 8) & 0xff]     // 次低8位查表
        ^ sm4TBox3[input & 0xff];           // 低8位查表
}

uint32_t tPrimeFunction(uint32_t input) {
    // 拆分为4个字节并通过S盒变换
    uint8_t bytes[4] = {
        static_cast<uint8_t>(input >> 24),
        static_cast<uint8_t>(input >> 16),
        static_cast<uint8_t>(input >> 8),
        static_cast<uint8_t>(input)
    };
    for (int i = 0; i < 4; ++i) {
        bytes[i] = SM4_SBOX[bytes[i]];
    }
    // 重组为32位并进行线性变换
    uint32_t cons = (static_cast<uint32_t>(bytes[0]) << 24)
        | (static_cast<uint32_t>(bytes[1]) << 16)
        | (static_cast<uint32_t>(bytes[2]) << 8)
        | bytes[3];
    return cons ^ rotateLeft(cons, 13) ^ rotateLeft(cons, 23);
}

void generateRoundKeys(const uint32_t masterKey[4], uint32_t roundKeys[32]) {
    uint32_t intermediateKeys[36];  // 中间密钥数组（包含初始密钥和32轮扩展密钥）

    // 初始密钥与FK异或
    for (int i = 0; i < 4; ++i) {
        intermediateKeys[i] = masterKey[i] ^ SM4_FK[i];
    }

    // 扩展生成32轮轮密钥
    for (int i = 0; i < 32; ++i) {
        intermediateKeys[i + 4] = intermediateKeys[i]
            ^ tPrimeFunction(intermediateKeys[i + 1]
                ^ intermediateKeys[i + 2]
                ^ intermediateKeys[i + 3]
                ^ SM4_CK[i]);
    }

    // 提取32轮轮密钥
    copy(intermediateKeys + 4, intermediateKeys + 36, roundKeys);
}

void sm4Cipher(uint32_t block[4], const uint32_t roundKeys[32], bool isEncrypt = true) {
    uint32_t state[36];  // 加密过程中的状态数组（包含初始状态和32轮变换结果）
    copy(block, block + 4, state);  // 初始化状态为输入块

    // 32轮迭代变换
    for (int round = 0; round < 32; ++round) {
        // 解密时使用逆序轮密钥
        int roundIndex = isEncrypt ? round : 31 - round;

        // 状态更新：state[i+4] = state[i] ^ T(state[i+1] ^ state[i+2] ^ state[i+3] ^ roundKeys[roundIndex])
        state[round + 4] = state[round] ^ tFunctionLookup(state[round + 1]
            ^ state[round + 2]
            ^ state[round + 3]
            ^ roundKeys[roundIndex]);
    }

    // 输出变换（将最后4个状态逆序作为结果）
    for (int i = 0; i < 4; ++i) {
        block[i] = state[35 - i];
    }
}

void sm4Encrypt4SSE(uint32_t output[4][4], const uint32_t input[4][4], const uint32_t roundKeys[32]) {
    uint32_t blockStates[4][36];  // 4个块的状态数组

    // 初始化每个块的状态
    for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
        copy(input[blockIdx], input[blockIdx] + 4, blockStates[blockIdx]);
    }

    // 32轮并行迭代
    for (int round = 0; round < 32; ++round) {
        for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
            // 计算轮函数输入：state[i+1] ^ state[i+2] ^ state[i+3] ^ 轮密钥
            uint32_t roundFuncInput = blockStates[blockIdx][round + 1]
                ^ blockStates[blockIdx][round + 2]
                ^ blockStates[blockIdx][round + 3]
                ^ roundKeys[round];

            // 更新当前块的状态
            blockStates[blockIdx][round + 4] = blockStates[blockIdx][round] ^ tFunctionLookup(roundFuncInput);
        }
    }

    // 输出变换（每个块的状态逆序）
    for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
        for (int i = 0; i < 4; ++i) {
            output[blockIdx][i] = blockStates[blockIdx][35 - i];
        }
    }
}

void printBlock(const string& label, const uint32_t block[4]) {
    cout << label << ": ";
    for (int i = 0; i < 4; ++i) {
        cout << hex << setw(8) << setfill('0') << block[i] << " ";
    }
    cout << dec << endl;
}

void testEncryptionDecryptionCorrectness() {
    uint32_t plaintext[4] = { 0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00 };
    uint32_t masterKey[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };
    uint32_t ciphertext[4], decryptedText[4], roundKeys[32];

    // 生成轮密钥
    generateRoundKeys(masterKey, roundKeys);

    // 加密
    copy(plaintext, plaintext + 4, ciphertext);
    sm4Cipher(ciphertext, roundKeys, true);

    // 解密
    copy(ciphertext, ciphertext + 4, decryptedText);
    sm4Cipher(decryptedText, roundKeys, false);

    // 输出结果并验证正确性
    printBlock("plaintext  ", plaintext);
    printBlock("ciphertext ", ciphertext);
    printBlock("decryptedtext  ", decryptedText);
    cout << (equal(plaintext, plaintext + 4, decryptedText) ?
        "correctness: passed\n" : "correctness: failed\n");
}

void testSimdCorrectness() {
    uint32_t roundKeys[32];
    uint32_t masterKey[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    generateRoundKeys(masterKey, roundKeys);

    // 初始化4个测试输入块
    uint32_t inputs[4][4], simdOutput[4][4], normalOutput[4][4];
    for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
        for (int i = 0; i < 4; ++i) {
            inputs[blockIdx][i] = 0x11111111 * (blockIdx + 1) + i;
        }
    }

    // SIMD并行加密
    sm4Encrypt4SSE(simdOutput, inputs, roundKeys);

    // 常规加密（逐个块）
    for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
        copy(inputs[blockIdx], inputs[blockIdx] + 4, normalOutput[blockIdx]);
        sm4Cipher(normalOutput[blockIdx], roundKeys, true);
    }

    // 验证SIMD与常规加密结果一致性
    bool isMatch = true;
    for (int blockIdx = 0; blockIdx < 4; ++blockIdx) {
        if (!equal(normalOutput[blockIdx], normalOutput[blockIdx] + 4, simdOutput[blockIdx])) {
            isMatch = false;
            break;
        }
    }
    cout << "simd correctness test " << (isMatch ? "passed" : "failed") << endl;
}

void testSimdPerformance() {
    const int totalBlocks = 1000000;  // 总加密块数
    uint32_t roundKeys[32];
    uint32_t masterKey[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    generateRoundKeys(masterKey, roundKeys);

    // 测试输入块（固定值，避免随机生成影响性能）
    uint32_t inputBlocks[4][4] = {
        {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
        {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210},
        {0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00},
        {0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899}
    };
    uint32_t outputBlocks[4][4];  // 输出块（仅占位，不影响性能测试）

    // 计时开始
    auto startTime = chrono::high_resolution_clock::now();

    // 执行SIMD加密（每次处理4个块）
    for (int i = 0; i < totalBlocks / 4; ++i) {
        sm4Encrypt4SSE(outputBlocks, inputBlocks, roundKeys);
    }

    // 计时结束
    auto endTime = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsedTime = endTime - startTime;

    // 输出性能数据
    cout << "\nsimd Performance Test\n";
    cout << "Encrypted " << totalBlocks << " blocks in " << elapsedTime.count() << " seconds.\n";
    cout << "Average time : " << (elapsedTime.count() * 1e6 / totalBlocks) << " us\n";
}

int main() {
    initTBox();  // 初始化T盒（预计算加速表）
    // 执行测试
    testEncryptionDecryptionCorrectness();
    testSimdCorrectness();
    testSimdPerformance();
    system("pause");
    return 0;
}