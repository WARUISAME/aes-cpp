﻿#include "AES.h"

AES::AES(const std::vector<uint8_t>& cipherKey, const bool aesniflag) : key(cipherKey), aesniSupported(checkAESNISupport(aesniflag)) {
    // 逆元テーブルの初期化
    initInverse();

    const bool AES128Flag = cipherKey.size() == AES_128;
    const bool AES192Flag = cipherKey.size() == AES_192;
    const bool AES256Flag = cipherKey.size() == AES_256;

    // Figure 4. Key-Block-Round Combination
    if (AES128Flag) { // AES-128
        Nk = 4;
        Nr = 10;
    }
    else if (AES192Flag) { // AES-192
        Nk = 6;
        Nr = 12;
    }
    else if (AES256Flag) { // AES-256
        Nk = 8;
        Nr = 14;
    }
    else {
        throw std::invalid_argument("Invalid key length");
    }

    // rdKeyとdecKeyのサイズを設定 (Nrはラウンド数なので Nr + 1 個の鍵が必要)
    rdKey.resize(Nr + 1);
    decKey.resize(Nr + 1);

    // AES-NIがサポートされている場合
    if (aesniSupported) {
        // 鍵拡張
        // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
        // p24 AES-128, AES-192, and AES-256 Key Expansion (C code)
        if (AES128Flag) {
            __m128i temp1_keyexp, temp2_keyexp;

            temp1_keyexp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(this->key.data()));
            rdKey[0] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x01);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[1] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x02);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[2] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x04);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[3] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x08);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[4] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x10);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[5] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x20);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[6] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x40);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[7] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x80);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[8] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x1b);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[9] = temp1_keyexp;

            temp2_keyexp = _mm_aeskeygenassist_si128(temp1_keyexp, 0x36);
            temp1_keyexp = aes128AssistImpl(temp1_keyexp, temp2_keyexp);
            rdKey[10] = temp1_keyexp;
        }
        else if (AES192Flag) {
            __m128i temp1, temp2, temp3;

            temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
            temp3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + 16));

            rdKey[0] = temp1;
            rdKey[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 0b01));

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x1);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[1] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rdKey[1]), _mm_castsi128_pd(temp1), 0b00));
            rdKey[2] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 0b01));

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x2);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[3] = temp1;
            rdKey[4] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x4);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[4] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rdKey[4]), _mm_castsi128_pd(temp1), 0b00));
            rdKey[5] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 0b01));

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x8);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[6] = temp1;
            rdKey[7] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[7] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rdKey[7]), _mm_castsi128_pd(temp1), 0b00));
            rdKey[8] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 0b01));

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[9] = temp1;
            rdKey[10] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[10] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(rdKey[10]), _mm_castsi128_pd(temp1), 0b00));
            rdKey[11] = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(temp1), _mm_castsi128_pd(temp3), 0b01));

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
            aes192Assist(&temp1, &temp2, &temp3);
            rdKey[12] = temp1;
        }
        else if (AES256Flag) {
            __m128i temp1, temp2, temp3;
            temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
            temp3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + 16));
            rdKey[0] = temp1;
            rdKey[1] = temp3;

            temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
            key256Assist1(&temp1, &temp2);
            rdKey[2] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[3] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
            key256Assist1(&temp1, &temp2);
            rdKey[4] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[5] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
            key256Assist1(&temp1, &temp2);
            rdKey[6] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[7] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
            key256Assist1(&temp1, &temp2);
            rdKey[8] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[9] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
            key256Assist1(&temp1, &temp2);
            rdKey[10] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[11] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
            key256Assist1(&temp1, &temp2);
            rdKey[12] = temp1;
            key256Assist2(&temp1, &temp3);
            rdKey[13] = temp3;
            temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
            key256Assist1(&temp1, &temp2);
            rdKey[14] = temp1;
        }

        // 復号用鍵生成
        decKey[0] = rdKey[Nr];
        for (size_t i = 1; i < Nr; ++i) {
            decKey[i] = _mm_aesimc_si128(rdKey[Nr - i]);
        }
        decKey[Nr] = rdKey[0];

#ifdef _DEBUG
        for (size_t i = 0; i < rdKey.size(); ++i) {
            uint8_t buf[16];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(buf), rdKey[i]);
            std::cout << "AES-NI round " << i << ": ";
            for (int j = 0; j < 16; ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buf[j];
            }
            std::cout << std::endl;
        }
#endif
    }
    else {
       keyScheduleWords = keyExpansion();
    }
}

AES::~AES() {
    // 鍵や鍵スケジュールなどの機密情報をメモリから安全に消去する
    if (!key.empty()) {
        secureZeroMemory(key.data(), key.size() * sizeof(key[0]));
    }
    if (!rdKey.empty()) {
        secureZeroMemory(rdKey.data(), rdKey.size() * sizeof(rdKey[0]));
    }
    if (!decKey.empty()) {
        secureZeroMemory(decKey.data(), decKey.size() * sizeof(decKey[0]));
    }
    if (!keyScheduleWords.empty()) {
        secureZeroMemory(keyScheduleWords.data(), keyScheduleWords.size() * sizeof(keyScheduleWords[0]));
    }
}

// CBCモードで暗号化
std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t>& plain_text) {
    if (!aesniSupported) {
        std::vector<uint8_t> iv = generateRandomBytes(ivSize);
        std::vector<uint8_t> padded_text = padInput(plain_text);
        std::vector<uint8_t> cipher_text = iv;

        std::vector<uint8_t> previous_block = iv;
        for (size_t i = 0; i < padded_text.size(); i += paddingSize) {
            std::vector<uint8_t> block(padded_text.begin() + i, padded_text.begin() + i + paddingSize);
            block = xorVectors(block, previous_block);
            std::vector<uint8_t> encrypted_block = cipher(block);
            cipher_text.insert(cipher_text.end(), encrypted_block.begin(), encrypted_block.end());
            previous_block = encrypted_block;
        }

        return cipher_text;
    }
    else {
        return encryptAESNI_cbc(plain_text);
    }
}

// CBCモードで復号化
std::vector<uint8_t> AES::decrypt_cbc(const std::vector<uint8_t>& cipher_text) {
    if (!aesniSupported) {
        std::vector<uint8_t> iv(cipher_text.begin(), cipher_text.begin() + paddingSize);
        std::vector<uint8_t> plain_text;

        std::vector<uint8_t> previous_block = iv;
        for (size_t i = paddingSize; i < cipher_text.size(); i += paddingSize) {
            std::vector<uint8_t> block(cipher_text.begin() + i, cipher_text.begin() + i + paddingSize);
            std::vector<uint8_t> decrypted_block = invCipher(block);
            std::vector<uint8_t> plain_block = xorVectors(decrypted_block, previous_block);
            plain_text.insert(plain_text.end(), plain_block.begin(), plain_block.end());
            previous_block = block;
        }

        return removePadding(plain_text);
    }
    else {
        return decryptAESNI_cbc(cipher_text);
    }
}

//----------ソフトウェア----------
State AES::subBytes(const State &s) {
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

State AES::invSubBytes(const State& s) {
    std::vector<uint8_t> res;
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            res.push_back(invSbox(s.get(r, c)));
        }
    }
    return State(res);
}

State AES::invShiftRows(const State& s) {
    State res({});
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            res.set(r, c, s.get(r, (c - r + 4) % 4));
        }
    }
    return res;
}

State AES::invMixColumns(const State& s) {
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

std::vector<uint32_t> AES::keyExpansion() {
    // Round contants : 5.2 KeyExpansion Table 5 p.17
    std::vector<uint8_t> rcon = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    std::vector<uint32_t> w(Nb * (Nr + 1), 0);

    // 初期鍵のロード（修正済みのエンディアン処理）
    for (int i = 0; i < Nk; ++i) {
        w[i] = byteArray2Word({
            key[4 * i],     // 最上位バイト
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3]    // 最下位バイト
            });
    }

    // 鍵拡張のメイン処理
    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            // Rconの正しい適用
            uint8_t rc = rcon[i / Nk];
            temp = subWord(rotWord(temp)) ^ (rc << 24);
        }
        else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }


    // デバッグ出力（最初と最後のラウンドキー）
#ifdef _DEBUG
    std::cout << "First round key: ";
    for (int i = 0; i < 4; ++i) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << w[i] << " ";
    }
    std::cout << "\nLast round key: ";
    for (size_t i = w.size() - 4; i < w.size(); ++i) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << w[i] << " ";
    }
    std::cout << std::endl;
#endif

    return w;
}

// Nk キーのワード数 ( 1ワード = 4バイト )
// Nr ラウンド数
// KeyExpansion: 暗号化キーから各ラウンドキーを生成
// Cipher: 暗号化
std::vector<uint8_t> AES::cipher(const std::vector<uint8_t> &inputBytes) {
    // 入力バイト列をStateの変換
    State st(inputBytes);

    // 初期ラウンドキーの追加
    st = addRoundKey(st, { keyScheduleWords.begin(), keyScheduleWords.begin() + Nb});

	// 1ラウンドからNr-1ラウンド
    for (int r = 1; r < Nr; ++r) {
        st = subBytes(st);
        st = shiftRows(st);
        st = mixColumns(st);
        st = addRoundKey(st, { keyScheduleWords.begin() + r * Nb, keyScheduleWords.begin() + (r + 1) * Nb});
    }

    // 最終ラウンド
    st = subBytes(st);
    st = shiftRows(st);
    st = addRoundKey(st, { keyScheduleWords.begin() + Nr * Nb, keyScheduleWords.begin() + (Nr + 1) * Nb});

    return st.getBytes();
}

std::vector<uint8_t> AES::invCipher(const std::vector<uint8_t>& inputBytes) {
    State st(inputBytes);

    st = addRoundKey(st, { keyScheduleWords.begin() + Nr * Nb, keyScheduleWords.begin() + (Nr + 1) * Nb });

    for (int r = Nr - 1; r > 0; --r) {
        st = invShiftRows(st);
        st = invSubBytes(st);
        st = addRoundKey(st, { keyScheduleWords.begin() + r * Nb, keyScheduleWords.begin() + (r + 1) * Nb });
        st = invMixColumns(st);
    }

    st = invShiftRows(st);
    st = invSubBytes(st);
    st = addRoundKey(st, { keyScheduleWords.begin(), keyScheduleWords.begin() + Nb });

    return st.getBytes();
}

//----------AES-NI----------

// AES-NIを使用してCBCモードで暗号化
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
// 29p AES Encryption and Decryption in CBC Mode 
std::vector<uint8_t> AES::encryptAESNI_cbc(const std::vector<uint8_t>& plain_text) {
    if (plain_text.size() == 0) return {};

    // パディング追加 (PKCS#7)
    size_t pad_len = paddingSize - (plain_text.size() % paddingSize);
    std::vector<uint8_t> padded(plain_text.begin(), plain_text.end());
    padded.resize(plain_text.size() + pad_len, static_cast<uint8_t>(pad_len));

#ifdef _DEBUG
    std::cout << "Padding added: " << static_cast<int>(pad_len)
        << " bytes\nPadded data:\n";
    for (size_t i = 0; i < plain_text.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)plain_text[i];
        if ((i + 1) % 16 == 0) {
            std::cout << '\n';
        }
        else {
            std::cout << ' ';
        }
    }
    std::cout << std::endl;
#endif

    // IV生成
    std::vector<uint8_t> iv(ivSize);
    std::random_device rd;
    std::generate(iv.begin(), iv.end(), [&]() { return rd(); });

    __m128i iv_block = _mm_loadu_si128(reinterpret_cast<__m128i*>(iv.data()));

    std::vector<uint8_t> cipher(iv.size() + padded.size());
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher.data()), iv_block);

    // CBC暗号化
    for (size_t i = 0; i < padded.size(); i += paddingSize) {
        __m128i plain_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(padded.data() + i));

        iv_block = _mm_xor_si128(plain_block, iv_block);
        iv_block = encryptBlock(iv_block);

        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(cipher.data() + iv.size() + i), iv_block);
    }

    return cipher;
}

// AES-NIを使用してCBCモードで復号化
std::vector<uint8_t> AES::decryptAESNI_cbc(const std::vector<uint8_t>& cipher_text) {
    if (cipher_text.size() < ivSize || (cipher_text.size() - ivSize) % Nb != 0) {
        throw std::invalid_argument("Invalid cipher length");
    }

    // IV抽出
    __m128i iv_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(cipher_text.data()));
    __m128i prev_block = iv_block;

    const size_t data_len = cipher_text.size() - ivSize;
    std::vector<uint8_t> plain(data_len);

    // CBC復号
    for (size_t i = ivSize; i < cipher_text.size(); i += paddingSize) {
        __m128i ct_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(cipher_text.data() + i));

        __m128i pt_block = decryptBlock(ct_block);
        pt_block = _mm_xor_si128(pt_block, prev_block);

        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(plain.data() + i - ivSize), pt_block);

        prev_block = ct_block;
    }

    // パディング削除
    size_t pad_len = plain.back();

    if (pad_len > paddingSize) throw std::runtime_error("Invalid padding");

    plain.resize(plain.size() - pad_len);
    return plain;
}

__m128i AES::encryptBlock(__m128i block) const {
    block = _mm_xor_si128(block, rdKey[0]);
    for (size_t i = 1; i < Nr; ++i) {
        block = _mm_aesenc_si128(block, rdKey[i]);
    }
    return _mm_aesenclast_si128(block, rdKey[Nr]);
}

__m128i AES::decryptBlock(__m128i block) const {
    block = _mm_xor_si128(block, decKey[0]);
    for (size_t i = 1; i < Nr; ++i) {
        block = _mm_aesdec_si128(block, decKey[i]);
    }
    return _mm_aesdeclast_si128(block, decKey[Nr]);
}

inline __m128i AES::aes128AssistImpl(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);

    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}

inline void AES::aes192Assist(__m128i* temp1, __m128i* temp2, __m128i* temp3) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, *temp2);
}

inline void AES::key256Assist1(__m128i *temp1, __m128i *temp2) {
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

inline void AES::key256Assist2(__m128i *temp1, __m128i *temp3) {
    __m128i temp2,temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x00);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}

//----------共通----------

std::vector<uint8_t> AES::generateRandomBytes(size_t length) {
    std::vector<uint8_t> random_bytes(length);
    std::random_device rd;

    for (size_t i = 0; i < length; ++i) {
        random_bytes[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    return random_bytes;
}

// XOR two vectors
std::vector<uint8_t> AES::xorVectors(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
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
std::vector<uint8_t> AES::padInput(const std::vector<uint8_t> &input) {
    size_t padding_size = 16 - (input.size() % 16);
    std::vector<uint8_t> padded = input;
    padded.insert(padded.end(), padding_size, static_cast<uint8_t>(padding_size));

    // デバッグ出力
#ifdef _DEBUG
    std::cout << "Padding added: " << static_cast<int>(padding_size)
        << " bytes\nPadded data:\n";
    for (size_t i = 0; i < padded.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)padded[i];
        if ((i + 1) % 16 == 0) {
            std::cout << '\n';
        }
        else {
            std::cout << ' ';
        }
    }
    std::cout << std::endl;
#endif
    return padded;
}

// 復号したテキストからパディングを削除
// Remove padding from the decrypted text
std::vector<uint8_t> AES::removePadding(const std::vector<uint8_t>& padded_input) {
    if (padded_input.size() < 16) {
        throw std::invalid_argument("Padded input too short");
    }

    const uint8_t padding_value = padded_input.back();
    if (padding_value == 0 || padding_value > 16) {
        throw std::invalid_argument("Invalid padding value");
    }

    // 全パディングバイトをチェック
    const size_t padding_start = padded_input.size() - padding_value;

    // デバッグ情報出力
#ifdef _DEBUG
    std::cerr << "Padding value detected: " << static_cast<int>(padding_value)
        << "\nLast 16 bytes:\n";
    for (size_t i = (padded_input.size() < 16) ? 0 : padded_input.size() - 16;
        i < padded_input.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)padded_input[i];
        if ((i + 1) % 16 == 0) {
            std::cout << '\n';
        }
        else {
            std::cout << ' ';
        }
    }
    for (size_t i = padding_start; i < padded_input.size(); ++i) {
        if (padded_input[i] != padding_value) {
            throw std::invalid_argument("Padding byte mismatch");
        }
    }
#endif

    return std::vector<uint8_t>(
        padded_input.begin(),
        padded_input.begin() + padding_start
    );
}

// ワードからバイト配列への変換（ビッグエンディアン）
std::vector<uint8_t> AES::word2ByteArray(uint32_t word) {
    std::vector<uint8_t> byteArray;
    byteArray.push_back((word >> 24) & 0xFF); // 最上位バイト
    byteArray.push_back((word >> 16) & 0xFF);
    byteArray.push_back((word >> 8) & 0xFF);
    byteArray.push_back(word & 0xFF);         // 最下位バイト
    return byteArray;
}

// バイト配列からワードへの変換（ビッグエンディアン）
uint32_t AES::byteArray2Word(const std::vector<uint8_t>& byteArray) {
    uint32_t res = 0;
    for (uint8_t byte : byteArray) {
        res = (res << 8) | byte;
    }
    return res;
}

// AES-NIがCPUにあるのか判定するプログラム
// 引数のフラグは任意でAES-NIを使用するかのフラグで、
// trueの場合でもCPUがAES-NIをサポートしていない場合はfalseを返します
bool AES::checkAESNISupport(const bool aesniflag) {
    if (!aesniflag) {
        return false;
    }

#if defined(_MSC_VER)
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    // ECXレジスタの25ビット目がAES-NIのサポートを示します ( (1 << 25) は 0x02000000 )
    return (cpuInfo[2] & (1 << 25)) != 0;
#elif (defined(__GNUC__))
    unsigned int eax = 1, ebx = 0, ecx = 0, edx = 0; // eaxにfunction_id = 1 をセット
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        // ECXレジスタの25ビット目がAES-NIのサポートを示します
        return (ecx & (1 << 25)) != 0;
    }
    return false; // サポートされていない
#else
    // AES-NIはサポートされていないと判断
    return false;
#endif
}

// メモリの内容をゼロクリアする
void AES::secureZeroMemory(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

