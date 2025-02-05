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

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

class AES {
public:
    AES();

    // Stateの各バイトをS-boxで置換
    State subBytes(const State& s);

    // Stateの各バイトを左にシフト
    State shiftRows(const State& s);

    // Stateの各列に対して多項式操作を行う
    State mixColumns(const State& s);

    // 32bitのワードを4バイトの配列に変換
    std::vector<uint8_t> word2ByteArray(uint32_t word);

    // 4バイトの配列を32bitのワードに変換
    uint32_t byteArray2Word(const std::vector<uint8_t>& byteArray);

    // StateとRoundKeyのXOR演算
    State addRoundKey(const State& st, const std::vector<uint32_t>& keyScheduleWords);
    
    // 32bitのワードの各バイトにS-box置換
    uint32_t subWord(uint32_t word);

    // 32bitのワードを1バイト左にシフト
    uint32_t rotWord(uint32_t word);

    // 暗号化キーから各ラウンドキーを生成
    std::vector<uint32_t> keyExpansion(const std::vector<uint8_t>& key, uint8_t Nk, uint8_t Nb, uint8_t Nr);

    // 暗号化
    std::vector<uint8_t> cipher(const std::vector<uint8_t>& inputBytes, const std::vector<uint32_t>& w, uint8_t Nb, uint8_t Nr);

    // 復号化
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input_bytes, const std::vector<uint8_t>& cipher_key);

    State invSubBytes(const State& s);

    State invShiftRows(const State& s);

    State invMixColumns(const State& s);

    std::vector<uint8_t> invCipher(const std::vector<uint8_t>& inputBytes, const std::vector<uint32_t>& w, uint8_t Nb, uint8_t Nr);

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key);

    // Existing encrypt and decrypt functions (single block)
    std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& input_bytes, const std::vector<uint8_t>& cipher_key);

    std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key);

    // Generate a random IV (Initialization Vector)
    std::vector<uint8_t> generate_iv();

    // XOR two vectors
    std::vector<uint8_t> xor_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

    // 入力を16バイトの倍数にパディングする (PKCS7パディング)
    // Pad the input to be a multiple of 16 bytes (PKCS7 padding)
    std::vector<uint8_t> pad_input(const std::vector<uint8_t>& input);

    // 復号したテキストからパディングを削除
    // Remove padding from the decrypted text
    std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& padded_input);

    // Encrypt using CBC mode
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plain_text, const std::vector<uint8_t>& cipher_key);

    // Decrypt using CBC mode
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key);

    // 任意のIVを指定してCBCモードで暗号化
    std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& plain_text, const std::vector<uint8_t>& cipher_key, const std::vector<uint8_t>& iv);

    // 任意のIVを指定してCBCモードで復号化
    std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key, const std::vector<uint8_t>& iv);


    // AES-NIを使用して暗号化
    std::vector<uint8_t> encryptAESNI_cbc(const std::vector<uint8_t>& plain_text, const std::vector<uint8_t>& cipher_key);

    // AES-NIを使用して複合化
    std::vector<uint8_t> decryptAESNI_cbc(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key);

private:

    const int Nb = 4; // ブロックサイズ
    int Nk = 8;
    int Nr = 14;
    const uint8_t paddingSize = 16;
};