#pragma once
#include <vector>
#include <cstdint>
#include <algorithm> // rotate
#include "State.h"
#include "Sbox.h"
#include "GFCPoly.h"
#include "GFPoly.h"

#include <stdexcept>
#include <random>
#include <cstring>

// AES-NI
#include <immintrin.h>
#include <wmmintrin.h>

// AES-NIがサポートされているかどうかを確認するためのヘッダー
#if defined(_MSC_VER)
    #include <intrin.h>
#elif defined(__GNUC__)
    #include <cpuid.h>
#endif

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

class AES {
public:
    AES(const std::vector<uint8_t>& cipherKey, const bool aesniflag);

    ~AES();

    // Encrypt using CBC mode
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plain_text);

    // Decrypt using CBC mode
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& cipher_text);

private:
    // --- ソフトウェア実装の関数 ---
    
    // Stateの各バイトをS-boxで置換
    State subBytes(const State& s);

    // Stateの各バイトを左にシフト
    State shiftRows(const State& s);

    // Stateの各列に対して多項式操作を行う
    State mixColumns(const State& s);

    // ubBytesの逆変換
    State invSubBytes(const State& s);

    // shiftRowsの逆変換
    State invShiftRows(const State& s);

    // mixColumnsの逆変換
    State invMixColumns(const State& s);

    // StateとRoundKeyのXOR演算
    State addRoundKey(const State& st, const std::vector<uint32_t>& keyScheduleWords);
    
    // 32bitのワードの各バイトにS-box置換
    uint32_t subWord(uint32_t word);

    // 32bitのワードを1バイト左にシフト
    uint32_t rotWord(uint32_t word);

    // 暗号化キーから各ラウンドキーを生成
    std::vector<uint32_t> keyExpansion();

    std::vector<uint8_t> cipher(const std::vector<uint8_t>& inputBytes);

    std::vector<uint8_t> invCipher(const std::vector<uint8_t>& inputBytes);

    // 暗号化
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input_bytes);

    // 復号化
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher_text);

    // --- AES-NI実装の関数 ---
    
    // AES-NIを使用してCBCモードで暗号化
    std::vector<uint8_t> encryptAESNI_cbc(const std::vector<uint8_t>& plain_text);
    // AES-NIを使用してCBCモードで復号化
    std::vector<uint8_t> decryptAESNI_cbc(const std::vector<uint8_t>& cipher_text);

    // AES-NIを使用してブロックを暗号化
    __m128i encrypt_block(__m128i block) const;
    // AES-NIを使用してブロックを復号化
    __m128i decrypt_block(__m128i block) const;

    // AES-128 のキー拡張用
    inline __m128i AES_128_ASSIST_IMPL(__m128i temp1, __m128i temp2);
    // AES-192 のキー拡張用
    inline void AES_192_ASSIST(__m128i* temp1, __m128i* temp2, __m128i* temp3);

    // AES-256 のキー拡張用
    inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i* temp2);
    inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i* temp3);

    // --- 共通の関数 ---
    
    // Generate a vector of random bytes of a given size.
    static std::vector<uint8_t> generare_random_bytes(size_t length);

    // XOR two vectors
    std::vector<uint8_t> xor_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // Pad the input to be a multiple of 16 bytes (PKCS7 padding)
    std::vector<uint8_t> pad_input(const std::vector<uint8_t>& input);

    // Remove padding from the decrypted text
    std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& padded_input);

    // 32bitのワードを4バイトの配列に変換
    std::vector<uint8_t> word2ByteArray(uint32_t word);

    // 4バイトの配列を32bitのワードに変換
    uint32_t byteArray2Word(const std::vector<uint8_t>& byteArray);

    // AES-NIがCPUにあるのか判定するプログラム
    bool check_aesni_support(const bool aesniflag);

    // メモリをゼロクリアする
    void secure_zero_memory(void* ptr, size_t len);

private:
    // AES-NIがサポートされているか true: サポートされている false: サポートされていない
    bool aesniSupported = false;

    const uint8_t AES_128 = 16;
    const uint8_t AES_192 = 24;
    const uint8_t AES_256 = 32;

    std::vector<uint8_t> key; // 暗号キー

    const uint8_t Nb = 4; // ブロックサイズ (ワード単位)
    uint8_t Nk = 0;       // キー長 (ワード単位)
    uint8_t Nr = 0;       // ラウンド数

    const uint8_t ivSize = 16;      // IVのサイズ (AESは16バイトのブロックサイズを持つ)
    const uint8_t paddingSize = 16; // パディングサイズ (PKCS7パディング)

    // AES-NI用の鍵スケジュール
    std::vector<__m128i> rd_key;
    std::vector<__m128i> dec_key;

    std::vector<uint32_t> keyScheduleWords; // ソフトウェア実装用の鍵スケジュール
};