#include "AES.h"

AES::AES()
{
    // 逆元テーブルの初期化
    initInverse();
}

State AES::subBytes(const State &s)
{
    std::vector<uint8_t> res;
    for(int c = 0; c < 4; c++){
        for(int r = 0; r < 4; r++){
            res.push_back(Sbox(s.get(r,c)));
        }
    }
    return State(res);
}

State AES::shiftRows(const State &s) {
    State res({});

    for(int r = 0; r < 4; r++){
        for(int c = 0; c < 4; c++){
            res.set(r, c, s.get(r, (c + r) % 4));
        }
    }
    return res;
}

State AES::mixColumns(const State &s) {
    State res({});
    // a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
    GFCPolynomial aPoly({0x02, 0x01, 0x01, 0x03});

    for (int c = 0; c < 4; c++) {
        GFCPolynomial sPoly({s.get(0, c), s.get(1, c), s.get(2, c), s.get(3, c)});
        std::vector<GFPolynomial> sdash = (aPoly * sPoly).getCs();

        for (int r = 0; r < 4; r++) {
            res.set(r, c, sdash[r].getCoeffs());
        }
    }

    return res;
}

std::vector<uint8_t> AES::word2ByteArray(uint32_t word) {
    std::vector<uint8_t> byteArray;
    for (int i = 0; i < 4; i++) {
        byteArray.push_back(word & 0xff);
        //byteArray[i] = word & 0xff;
        word >>= 8;
    }
    return byteArray;
}

uint32_t AES::byteArray2Word(const std::vector<uint8_t> &byteArray) {
    uint32_t res = 0;
    for (auto it = byteArray.rbegin(); it != byteArray.rend(); ++it) {
        res <<= 8;
        res += *it;
    }
    return res;
}

State AES::addRoundKey(const State &st, const std::vector<uint32_t> &keyScheduleWords) {
    State res({});

    for (int c = 0; c < 4; ++c) {
        GFCPolynomial sPoly({st.get(0, c), st.get(1, c), st.get(2, c), st.get(3, c)});
        std::vector<uint8_t> byteArray = word2ByteArray(keyScheduleWords[c]);
        GFCPolynomial wPoly(byteArray);

        GFCPolynomial sdash = sPoly + wPoly;

        for (int r = 0; r < 4; ++r) {
            res.set(r, c, sdash.getCs()[r].getCoeffs());
        }
    }

    return res;
}

/*
5.3 Key Expansion SubWord() p.19. word -> [sbox(a0),sbox(a1),sbox(a2),sbox(a3)] -> sub_word
:param word: 1 word integer
:type word: int
:rtype: int
*/
uint32_t AES::subWord(uint32_t word) {
    std::vector<uint8_t> byteArray = word2ByteArray(word);
    for (uint8_t& byte : byteArray) {
        byte = Sbox(byte);
    }
    return byteArray2Word(byteArray);
}

/*
5.3 Key Expasion RotWord. [a0, a1, a2, a3] -> [a1, a2, a3, a0]
:param word: 1 word integer
:type word: int
:rtype: int
*/
uint32_t AES::rotWord(uint32_t word) {
    std::vector<uint8_t> byteArray = word2ByteArray(word);
    std::rotate(byteArray.begin(), byteArray.begin() + 1, byteArray.end());
    return byteArray2Word(byteArray);
}

std::vector<uint32_t> AES::keyExpansion(const std::vector<uint8_t> &key, uint8_t Nk, uint8_t Nb, uint8_t Nr) {
    std::vector<uint32_t> rcon(Nb * (Nr + 1) / Nk + 1);
    rcon[0] = 0;

    for (int i = 1; i < rcon.size(); ++i) {
        GFPolynomial poly(1 << (i - 1));
        rcon[i] = byteArray2Word({poly.getCoeffs(), 0, 0, 0});
    }

    std::vector<uint32_t> w(Nb * (Nr + 1), 0);
    for (int i = 0; i < Nk; ++i) {
        w[i] = byteArray2Word({key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]});
    }

    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp)) ^ rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }

    return w;
}

std::vector<uint8_t> AES::cipher(const std::vector<uint8_t> &inputBytes, const std::vector<uint32_t> &w, uint8_t Nb, uint8_t Nr) {
    // 入力バイト列をStateの変換
    State st(inputBytes);

    // 初期ラウンドキーの追加
    st = addRoundKey(st, {w.begin(), w.begin() + Nb});

	// 1ラウンドからNr-1ラウンド
    for (int r = 1; r < Nr; ++r) {
        st = subBytes(st);
        st = shiftRows(st);
        st = mixColumns(st);
        st = addRoundKey(st, {w.begin() + r * Nb, w.begin() + (r + 1) * Nb});
    }

    // 最終ラウンド
    st = subBytes(st);
    st = shiftRows(st);
    st = addRoundKey(st, {w.begin() + Nr * Nb, w.begin() + (Nr + 1) * Nb});

    return st.getBytes();
}

// Nk キーのワード数 ( 1ワード = 4バイト )
// Nr ラウンド数
// KeyExpansion: 暗号化キーから各ラウンドキーを生成
// Cipher: 暗号化
std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t> &input_bytes, const std::vector<uint8_t> &cipher_key) {
    // Figure 4. Key-Block-Round Combinations
    int Nk, Nr;
    if (cipher_key.size() == 16) { // AES-128
        Nk = 4;
        Nr = 10;
    } else if (cipher_key.size() == 24) { // AES-192
        Nk = 6;
        Nr = 12;
        // Handle AES-192 case as needed
    } else if (cipher_key.size() == 32) { // AES-256
        Nk = 8;
        Nr = 14;
        // Handle AES-256 case as needed
    } else {
        // Handle error: cipher_key byte length must be 16, 24, or 32
    }

    std::vector<uint32_t> w = keyExpansion(cipher_key, Nk, Nb, Nr);
    return cipher(input_bytes, w, Nb, Nr);
}

//----------Decrypt----------

State AES::invSubBytes(const State &s) {
    std::vector<uint8_t> res;
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            res.push_back(invSbox(s.get(r, c)));
        }
    }
    return State(res);
}

State AES::invShiftRows(const State &s) {
    State res({});
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            res.set(r, c, s.get(r, (c - r + 4) % 4));
        }
    }
    return res;
}

State AES::invMixColumns(const State &s) {
    State res({});
    // a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}
    GFCPolynomial aInvPoly({ 0x0e, 0x09, 0x0d, 0x0b });

    for (int c = 0; c < 4; c++) {
        GFCPolynomial sPoly({ s.get(0, c), s.get(1, c), s.get(2, c), s.get(3, c) });
        std::vector<GFPolynomial> sdash = (aInvPoly * sPoly).getCs();

        for (int r = 0; r < 4; r++) {
            res.set(r, c, sdash[r].getCoeffs());
        }
    }

    return res;
}

std::vector<uint8_t> AES::invCipher(const std::vector<uint8_t> &inputBytes, const std::vector<uint32_t> &w, uint8_t Nb, uint8_t Nr) {
    State st(inputBytes);

    st = addRoundKey(st, { w.begin() + Nr * Nb, w.begin() + (Nr + 1) * Nb });

    for (int r = Nr - 1; r > 0; --r) {
        st = invShiftRows(st);
        st = invSubBytes(st);
        st = addRoundKey(st, { w.begin() + r * Nb, w.begin() + (r + 1) * Nb });
        st = invMixColumns(st);
    }

    st = invShiftRows(st);
    st = invSubBytes(st);
    st = addRoundKey(st, { w.begin(), w.begin() + Nb });

    return st.getBytes();
}

std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t> &cipher_text, const std::vector<uint8_t> &cipher_key) {
    int Nk, Nr;
    if (cipher_key.size() == 16) { // AES-128
        Nk = 4;
        Nr = 10;
    }
    else if (cipher_key.size() == 24) { // AES-192
        Nk = 6;
        Nr = 12;
    }
    else if (cipher_key.size() == 32) { // AES-256
        Nk = 8;
        Nr = 14;
    }
    else {
        // Handle error: cipher_key byte length must be 16, 24, or 32
        throw std::invalid_argument("Invalid key length");
    }

    std::vector<uint32_t> w = keyExpansion(cipher_key, Nk, Nb, Nr);
    return invCipher(cipher_text, w, Nb, Nr);
}

//----------CBC Mode----------

std::vector<uint8_t> AES::encrypt_block(const std::vector<uint8_t> &input_bytes, const std::vector<uint8_t> &cipher_key) {
    return encrypt(input_bytes, cipher_key);
}

std::vector<uint8_t> AES::decrypt_block(const std::vector<uint8_t> &cipher_text, const std::vector<uint8_t> &cipher_key) {
    return decrypt(cipher_text, cipher_key);
}

// Generate a random IV (Initialization Vector)
std::vector<uint8_t> AES::generate_iv() {
    std::vector<uint8_t> iv(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 16; ++i) {
        iv[i] = static_cast<uint8_t>(dis(gen));
    }

    return iv;
}

// XOR two vectors
std::vector<uint8_t> AES::xor_vectors(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Vectors must be of the same size for XOR operation");
    }

    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

// 入力を16バイトの倍数にパディングする (PKCS7パディング)
// Pad the input to be a multiple of 16 bytes (PKCS7 padding)
std::vector<uint8_t> AES::pad_input(const std::vector<uint8_t> &input) {
    size_t padding_size = 16 - (input.size() % 16);
    std::vector<uint8_t> padded = input;
    padded.insert(padded.end(), padding_size, static_cast<uint8_t>(padding_size));
    return padded;
}

// 復号したテキストからパディングを削除
// Remove padding from the decrypted text
std::vector<uint8_t> AES::remove_padding(const std::vector<uint8_t> &padded_input) {
    if (padded_input.empty()) {
        throw std::invalid_argument("Input is empty");
    }

    uint8_t padding_size = padded_input.back();
    if (padding_size > 16 || padding_size == 0) {
        throw std::invalid_argument("Invalid padding");
    }

    for (int i = 1; i <= padding_size; ++i) {
        if (padded_input[padded_input.size() - i] != padding_size) {
            throw std::invalid_argument("Invalid padding");
        }
    }

    return std::vector<uint8_t>(padded_input.begin(), padded_input.end() - padding_size);
}

// Encrypt using CBC mode
// cipher_textの先頭16バイトにIVが格納される
std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t> &plain_text, const std::vector<uint8_t> &cipher_key) {
    std::vector<uint8_t> iv = generate_iv();
    std::vector<uint8_t> padded_text = pad_input(plain_text);
    std::vector<uint8_t> cipher_text = iv;

    std::vector<uint8_t> previous_block = iv;
    for (size_t i = 0; i < padded_text.size(); i += 16) {
        std::vector<uint8_t> block(padded_text.begin() + i, padded_text.begin() + i + 16);
        block = xor_vectors(block, previous_block);
        std::vector<uint8_t> encrypted_block = encrypt_block(block, cipher_key);
        cipher_text.insert(cipher_text.end(), encrypted_block.begin(), encrypted_block.end());
        previous_block = encrypted_block;
    }

    return cipher_text;
}

// Decrypt using CBC mode
// cipher_textの先頭16バイトにIVが格納されているので、それを取り出して復号化
std::vector<uint8_t> AES::decrypt_cbc(const std::vector<uint8_t> &cipher_text, const std::vector<uint8_t> &cipher_key) {
    if (cipher_text.size() < 32 || cipher_text.size() % 16 != 0) {
        throw std::invalid_argument("Invalid cipher text length");
    }

    std::vector<uint8_t> iv(cipher_text.begin(), cipher_text.begin() + 16);
    std::vector<uint8_t> plain_text;

    std::vector<uint8_t> previous_block = iv;
    for (size_t i = 16; i < cipher_text.size(); i += 16) {
        std::vector<uint8_t> block(cipher_text.begin() + i, cipher_text.begin() + i + 16);
        std::vector<uint8_t> decrypted_block = decrypt_block(block, cipher_key);
        std::vector<uint8_t> plain_block = xor_vectors(decrypted_block, previous_block);
        plain_text.insert(plain_text.end(), plain_block.begin(), plain_block.end());
        previous_block = block;
    }

    return remove_padding(plain_text);
}

// 任意のIVを指定してCBCモードで暗号化
std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t> &plain_text, const std::vector<uint8_t> &cipher_key, const std::vector<uint8_t> &iv) {
    std::vector<uint8_t> padded_text = pad_input(plain_text);
    std::vector<uint8_t> cipher_text;

    std::vector<uint8_t> previous_block = iv;
    for (size_t i = 0; i < padded_text.size(); i += 16) {
        std::vector<uint8_t> block(padded_text.begin() + i, padded_text.begin() + i + 16);
        block = xor_vectors(block, previous_block);
        std::vector<uint8_t> encrypted_block = encrypt_block(block, cipher_key);
        cipher_text.insert(cipher_text.end(), encrypted_block.begin(), encrypted_block.end());
        previous_block = encrypted_block;
    }

    return cipher_text;
}

// 任意のIVを指定してCBCモードで復号化
std::vector<uint8_t> AES::decrypt_cbc(const std::vector<uint8_t> &cipher_text, const std::vector<uint8_t> &cipher_key, const std::vector<uint8_t> &iv) {
    std::vector<uint8_t> plain_text;
    std::vector<uint8_t> previous_block = iv;

    for (size_t i = 0; i < cipher_text.size(); i += 16) {
        std::vector<uint8_t> block(cipher_text.begin() + i, cipher_text.begin() + i + 16);
        std::vector<uint8_t> decrypted_block = decrypt_block(block, cipher_key);
        std::vector<uint8_t> plain_block = xor_vectors(decrypted_block, previous_block);
        plain_text.insert(plain_text.end(), plain_block.begin(), plain_block.end());
        previous_block = block;
    }

    return remove_padding(plain_text);
}



#include <immintrin.h>
// AES-NIを使用して暗号化
std::vector<uint8_t> AES::encryptAESNI_cbc(const std::vector<uint8_t>& plain_text, const std::vector<uint8_t>& cipher_key) {
    // IVを生成する
    std::vector<uint8_t> iv = generate_iv();
    std::vector<uint8_t> padded_text = pad_input(plain_text);
    // 暗号文の最初にIVを追加
    std::vector<uint8_t> cipher_text = iv;

    __m128i previous_block = _mm_loadu_si128((const __m128i*)iv.data());
    std::vector<uint32_t> w = keyExpansion(cipher_key, Nk, Nb, Nr); // ラウンドキーの生成
    for (size_t i = 0; i < padded_text.size(); i += paddingSize) {
        std::vector<uint8_t> block(padded_text.begin() + i, padded_text.begin() + i + paddingSize);
        __m128i block_m128 = _mm_loadu_si128((const __m128i*)block.data());
        // XOR 演算
        block_m128 = _mm_xor_si128(block_m128, previous_block);
        // AES 暗号化ラウンド
        __m128i roundKey = _mm_loadu_si128((const __m128i*) & w[0]);
        block_m128 = _mm_xor_si128(block_m128, roundKey);
        for (int r = 1; r < Nr; r++) {
            roundKey = _mm_loadu_si128((const __m128i*) & w[r * Nb]);
            block_m128 = _mm_aesenc_si128(block_m128, roundKey);
        }
        roundKey = _mm_loadu_si128((const __m128i*) & w[Nr * Nb]);
        block_m128 = _mm_aesenclast_si128(block_m128, roundKey);
        _mm_storeu_si128((__m128i*)block.data(), block_m128);
        cipher_text.insert(cipher_text.end(), block.begin(), block.end());
        previous_block = block_m128;
    }
    return cipher_text;
}

// AES-NIを使用してCBCモードで復号化
std::vector<uint8_t> AES::decryptAESNI_cbc(const std::vector<uint8_t>& cipher_text, const std::vector<uint8_t>& cipher_key) {
    std::vector<uint8_t> iv(cipher_text.begin(), cipher_text.begin() + paddingSize);
    std::vector<uint8_t> plain_text;

    __m128i previous_block = _mm_loadu_si128((const __m128i*)iv.data());
    std::vector<uint32_t> w = keyExpansion(cipher_key, Nk, Nb, Nr); // ラウンドキーの生成
    for (size_t i = paddingSize; i < cipher_text.size(); i += paddingSize) {
        std::vector<uint8_t> block(cipher_text.begin() + i, cipher_text.begin() + i + paddingSize);
        __m128i block_m128 = _mm_loadu_si128((const __m128i*)block.data());
        // AES 復号化ラウンド
        __m128i roundKey = _mm_loadu_si128((const __m128i*) & w[Nr * Nb]);
        for (int r = Nr - 1; r > 0; r--) {
            roundKey = _mm_loadu_si128((const __m128i*) & w[r * Nb]);
            block_m128 = _mm_aesdec_si128(block_m128, roundKey);
        }
        roundKey = _mm_loadu_si128((const __m128i*) & w[0]);
        block_m128 = _mm_aesdeclast_si128(block_m128, _mm_loadu_si128((const __m128i*)(cipher_key.data())));
        // XOR 演算
        block_m128 = _mm_xor_si128(block_m128, previous_block);
        _mm_storeu_si128((__m128i*)block.data(), block_m128);
        plain_text.insert(plain_text.end(), block.begin(), block.end());
        previous_block = _mm_loadu_si128((const __m128i*)(cipher_text.data() + i));
    }

    return remove_padding(plain_text);
}