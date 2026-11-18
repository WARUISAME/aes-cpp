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
#include <array>

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
    AES(const std::vector<uint8_t>& cipherKey, const bool aesniflag = true);
    AES(const AES& other);

    ~AES();

    // 暗号化ブロック
    std::vector<uint8_t> cipher(const std::vector<uint8_t>& inputBytes);

    // 復号化ブロック
    std::vector<uint8_t> invCipher(const std::vector<uint8_t>& inputBytes);

    // Encrypt using CBC mode
    // CBC has no authentication; use GCM/GCM-SIV for untrusted messages.
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plainText);

    // Decrypt using CBC mode
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& cipherText);

    // Encrypt using GCM mode
    std::vector<uint8_t> encrypt_gcm(const std::vector<uint8_t>& plainText,
                                      const std::vector<uint8_t>& additionalData = {});

    // Returns nonce || ciphertext || tag, like encrypt_gcm.
    // The caller MUST use a unique 12-byte nonce for every message under a key.
    std::vector<uint8_t> encrypt_gcm_with_nonce(const std::vector<uint8_t>& plainText,
                                      const std::vector<uint8_t>& nonce,
                                      const std::vector<uint8_t>& additionalData = {});

    // Decrypt using GCM mode
    std::vector<uint8_t> decrypt_gcm(const std::vector<uint8_t>& cipherText,
                                      const std::vector<uint8_t>& additionalData = {});

    // Encrypt using GCM-SIV mode (RFC 8452)
    // AES-128 and AES-256 only (AES-192 is not defined for GCM-SIV)
    std::vector<uint8_t> encrypt_gcm_siv(const std::vector<uint8_t>& plainText,
                                          const std::vector<uint8_t>& additionalData = {});

    // Decrypt using GCM-SIV mode (RFC 8452)
    std::vector<uint8_t> decrypt_gcm_siv(const std::vector<uint8_t>& cipherText,
                                          const std::vector<uint8_t>& additionalData = {});

private:
    // --- ソフトウェア実装の関数 ---
    
    // Stateの各バイトをS-boxで置換
    State subBytes(const State& s);

    // Stateの各バイトを左にシフト
    State shiftRows(const State& s);

    // Stateの各列に対して多項式操作を行う
    State mixColumns(const State& s);

    // subBytesの逆変換
    State invSubBytes(const State& s);

    // shiftRowsの逆変換
    State invShiftRows(const State& s);

    // mixColumnsの逆変換
    State invMixColumns(const State& s);

    // StateとRoundKeyのXOR演算
    State addRoundKey(const State& st, size_t round);
    
    // 32bitのワードの各バイトにS-box置換
    uint32_t subWord(uint32_t word);

    // 32bitのワードを1バイト左にシフト
    uint32_t rotWord(uint32_t word);

    // 暗号化キーから各ラウンドキーを生成
    std::vector<uint32_t> keyExpansion();

    // --- GCM実装の関数 ---
    
    // GCMを使用してCTRモードで暗号化/復号化
    std::vector<uint8_t> encryptGCM_ctr(const std::vector<uint8_t>& plainText, const std::vector<uint8_t>& iv, uint32_t counterStart = 2);
    std::vector<uint8_t> decryptGCM_ctr(const std::vector<uint8_t>& cipherText, const std::vector<uint8_t>& iv, uint32_t counterStart = 2);
    
    // GF(2^128) での乗算
    std::vector<uint8_t> gfMultiply(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y);
    
    // GHASH関数
    std::vector<uint8_t> ghash(const std::vector<uint8_t>& h, const std::vector<uint8_t>& data);
    
    // カウンターブロックの生成
    std::vector<uint8_t> generateCounterBlock(const std::vector<uint8_t>& iv, uint32_t counter);
    
    // GCTR関数（CTRモードの暗号化/復号化）
    std::vector<uint8_t> gctr(const std::vector<uint8_t>& icb, const std::vector<uint8_t>& data);

    // --- GCM-SIV実装の関数 (RFC 8452) ---
    
    // POLYVAL用のGF(2^128)乗算（LE convention, reducing polynomial: x^128+x^127+x^126+x^121+1）
    std::vector<uint8_t> polyvalMultiply(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    
    // POLYVAL関数
    std::vector<uint8_t> polyval(const std::vector<uint8_t>& h, const std::vector<uint8_t>& data);
    
    // GCM-SIV鍵導出（master keyからauth_keyとenc_keyを導出）
    void deriveGcmSivKeys(const std::vector<uint8_t>& nonce,
                           std::vector<uint8_t>& authKey,
                           std::vector<uint8_t>& encKey);
    
    // GCM-SIV用CTRモード暗号化/復号化（tagをカウンター初期値として使用）
    std::vector<uint8_t> gcmSivCtr(const std::vector<uint8_t>& tag,
                                    const std::vector<uint8_t>& data,
                                    const std::vector<uint8_t>& encKey);
    
    // 定数時間比較（タイミング攻撃対策）
    bool constantTimeCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // --- AES-NI実装の関数 ---
    
    // AES-NIを使用してCBCモードで暗号化
    std::vector<uint8_t> encryptAESNI_cbc(const std::vector<uint8_t>& plainText);
    // AES-NIを使用してCBCモードで復号化
    std::vector<uint8_t> decryptAESNI_cbc(const std::vector<uint8_t>& cipherText);

    // AES-NIを使用してブロックを暗号化
    __m128i encryptBlock(__m128i block) const;
    // AES-NIを使用してブロックを復号化
    __m128i decryptBlock(__m128i block) const;

    // AES-128 のキー拡張用
    inline __m128i aes128AssistImpl(__m128i temp1, __m128i temp2);
    // AES-192 のキー拡張用
    inline void aes192Assist(__m128i* temp1, __m128i* temp2, __m128i* temp3);

    // AES-256 のキー拡張用
    inline void key256Assist1(__m128i* temp1, __m128i* temp2);
    inline void key256Assist2(__m128i* temp1, __m128i* temp3);

    // --- 共通の関数 ---
    
    // Generate a vector of random bytes of a given size.
    static std::vector<uint8_t> generateRandomBytes(size_t length);

    // XOR two vectors
    std::vector<uint8_t> xorVectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // Pad the input to be a multiple of 16 bytes (PKCS7 padding)
    std::vector<uint8_t> padInput(const std::vector<uint8_t>& input);

    // Remove padding from the decrypted text
    std::vector<uint8_t> removePadding(const std::vector<uint8_t>& paddedInput);

    // 32bitのワードを4バイトの配列に変換
    std::vector<uint8_t> word2ByteArray(uint32_t word);

    // 4バイトの配列を32bitのワードに変換
    uint32_t byteArray2Word(const std::vector<uint8_t>& byteArray);

    // AES-NIがCPUにあるのか判定するプログラム
    bool checkAESNISupport(const bool aesniflag);

    // メモリをゼロクリアする
    void secureZeroMemory(void* ptr, size_t len);

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

    // Byte-backed slots avoid over-aligned allocations on pre-C++17 Win32.
    struct RoundKey {
        std::array<uint8_t, 16> bytes{};
        RoundKey& operator=(__m128i value) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes.data()), value);
            return *this;
        }
        operator __m128i() const {
            return _mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes.data()));
        }
    };
    std::vector<RoundKey> rdKey;
    std::vector<RoundKey> decKey;

    // GCM用の定数
    const uint8_t gcmIvSize = 12;    // GCMでは96ビット（12バイト）のIVを推奨
    const uint8_t gcmTagSize = 16;   // 認証タグのサイズ（128ビット）

    std::vector<uint32_t> keyScheduleWords; // ソフトウェア実装用の鍵スケジュール
};
