#include "AES.h"

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
            std::cout << std::dec << std::endl;
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
std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t>& plainText) {
    if (!aesniSupported) {
        std::vector<uint8_t> iv = generateRandomBytes(ivSize);
        std::vector<uint8_t> paddedText = padInput(plainText);
        std::vector<uint8_t> cipherText = iv;

        std::vector<uint8_t> previousBlock = iv;
        for (size_t i = 0; i < paddedText.size(); i += paddingSize) {
            std::vector<uint8_t> block(paddedText.begin() + i, paddedText.begin() + i + paddingSize);
            block = xorVectors(block, previousBlock);
            std::vector<uint8_t> encryptedBlock = cipher(block);
            cipherText.insert(cipherText.end(), encryptedBlock.begin(), encryptedBlock.end());
            previousBlock = encryptedBlock;
        }

        return cipherText;
    }
    else {
        return encryptAESNI_cbc(plainText);
    }
}

// CBCモードで復号化
std::vector<uint8_t> AES::decrypt_cbc(const std::vector<uint8_t>& cipherText) {
    if (!aesniSupported) {
        std::vector<uint8_t> iv(cipherText.begin(), cipherText.begin() + paddingSize);
        std::vector<uint8_t> plainText;

        std::vector<uint8_t> previousBlock = iv;
        for (size_t i = paddingSize; i < cipherText.size(); i += paddingSize) {
            std::vector<uint8_t> block(cipherText.begin() + i, cipherText.begin() + i + paddingSize);
            std::vector<uint8_t> decryptedBlock = invCipher(block);
            std::vector<uint8_t> plainBlock = xorVectors(decryptedBlock, previousBlock);
            plainText.insert(plainText.end(), plainBlock.begin(), plainBlock.end());
            previousBlock = block;
        }

        return removePadding(plainText);
    }
    else {
        return decryptAESNI_cbc(cipherText);
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
    std::cout << std::dec << std::endl;
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

//----------GCM----------
// GCMモードで暗号化
std::vector<uint8_t> AES::encrypt_gcm(const std::vector<uint8_t>& plainText) {

    // IV生成（96ビット）
    std::vector<uint8_t> iv = generateRandomBytes(gcmIvSize);
    
    // ハッシュサブキーHを生成（暗号化キーで0ブロックを暗号化）
    std::vector<uint8_t> zeroBlock(16, 0);
    std::vector<uint8_t> h;
    
    if (aesniSupported) {
        __m128i zero = _mm_setzero_si128();
        __m128i h_block = encryptBlock(zero);
        h.resize(16);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(h.data()), h_block);
    } else {
        h = cipher(zeroBlock);
    }
    
    // CTRモードで暗号化
    std::vector<uint8_t> cipherText = encryptGCM_ctr(plainText, iv, 2);
    
    // 認証データの準備（今回は空）
    std::vector<uint8_t> additionalData;
    
    // 長さ情報の準備
    uint64_t aad_len = additionalData.size() * 8;  // ビット単位
    uint64_t cipher_len = cipherText.size() * 8;   // ビット単位
    
    std::vector<uint8_t> length_block(16, 0);
    // ビッグエンディアンで長さを格納
    for (int i = 7; i >= 0; --i) {
        length_block[7 - i] = (aad_len >> (i * 8)) & 0xFF;
        length_block[15 - i] = (cipher_len >> (i * 8)) & 0xFF;
    }
    
    // GHASH計算用のデータを準備
    std::vector<uint8_t> ghash_data;
    ghash_data.insert(ghash_data.end(), additionalData.begin(), additionalData.end());
    
    // AADのパディング
    size_t aad_padding = (16 - (additionalData.size() % 16)) % 16;
    ghash_data.insert(ghash_data.end(), aad_padding, 0);
    
    ghash_data.insert(ghash_data.end(), cipherText.begin(), cipherText.end());
    
    // 暗号文のパディング
    size_t cipher_padding = (16 - (cipherText.size() % 16)) % 16;
    ghash_data.insert(ghash_data.end(), cipher_padding, 0);
    
    ghash_data.insert(ghash_data.end(), length_block.begin(), length_block.end());
    
    // GHASH計算
    std::vector<uint8_t> ghash_result = ghash(h, ghash_data);
    
    // J0の生成（IVが96ビットの場合）
    std::vector<uint8_t> j0 = iv;
    j0.insert(j0.end(), {0, 0, 0, 1});  // 32ビットのカウンター（初期値1）
    
    // 認証タグの生成
    std::vector<uint8_t> auth_tag;
    if (aesniSupported) {
        __m128i j0_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0.data()));
        __m128i encrypted_j0 = encryptBlock(j0_block);
        __m128i ghash_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_result.data()));
        __m128i tag_block = _mm_xor_si128(encrypted_j0, ghash_block);
        
        auth_tag.resize(16);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(auth_tag.data()), tag_block);
    } else {
        std::vector<uint8_t> encrypted_j0 = cipher(j0);
        auth_tag = xorVectors(encrypted_j0, ghash_result);
    }
    
    // 結果の構築: IV + 暗号文 + 認証タグ
    std::vector<uint8_t> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), cipherText.begin(), cipherText.end());
    result.insert(result.end(), auth_tag.begin(), auth_tag.end());
    
    return result;
}

// GCMモードで復号化
std::vector<uint8_t> AES::decrypt_gcm(const std::vector<uint8_t>& cipherText) {
    if (cipherText.size() < gcmIvSize + gcmTagSize) {
        throw std::invalid_argument("Invalid GCM cipher text length");
    }
    
    // IV、暗号文、認証タグを分離
    std::vector<uint8_t> iv(cipherText.begin(), cipherText.begin() + gcmIvSize);
    std::vector<uint8_t> encrypted_data(
        cipherText.begin() + gcmIvSize, 
        cipherText.end() - gcmTagSize
    );
    std::vector<uint8_t> received_tag(
        cipherText.end() - gcmTagSize, 
        cipherText.end()
    );
    
    // ハッシュサブキーHを生成
    std::vector<uint8_t> zero_block(16, 0);
    std::vector<uint8_t> h;
    
    if (aesniSupported) {
        __m128i zero = _mm_setzero_si128();
        __m128i h_block = encryptBlock(zero);
        h.resize(16);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(h.data()), h_block);
    } else {
        h = cipher(zero_block);
    }
    
    // 認証の検証
    std::vector<uint8_t> additionalData;  // 空のAAD
    
    uint64_t aad_len = additionalData.size() * 8;
    uint64_t cipher_len = encrypted_data.size() * 8;
    
    std::vector<uint8_t> length_block(16, 0);
    for (int i = 7; i >= 0; --i) {
        length_block[7 - i] = (aad_len >> (i * 8)) & 0xFF;
        length_block[15 - i] = (cipher_len >> (i * 8)) & 0xFF;
    }
    
    std::vector<uint8_t> ghash_data;
    ghash_data.insert(ghash_data.end(), additionalData.begin(), additionalData.end());
    
    size_t aad_padding = (16 - (additionalData.size() % 16)) % 16;
    ghash_data.insert(ghash_data.end(), aad_padding, 0);
    
    ghash_data.insert(ghash_data.end(), encrypted_data.begin(), encrypted_data.end());
    
    size_t cipher_padding = (16 - (encrypted_data.size() % 16)) % 16;
    ghash_data.insert(ghash_data.end(), cipher_padding, 0);
    
    ghash_data.insert(ghash_data.end(), length_block.begin(), length_block.end());
    
    std::vector<uint8_t> ghash_result = ghash(h, ghash_data);
    
    // J0の生成
    std::vector<uint8_t> j0 = iv;
    j0.insert(j0.end(), {0, 0, 0, 1});
    
    // 期待される認証タグの計算
    std::vector<uint8_t> expected_tag;
    if (aesniSupported) {
        __m128i j0_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0.data()));
        __m128i encrypted_j0 = encryptBlock(j0_block);
        __m128i ghash_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_result.data()));
        __m128i tag_block = _mm_xor_si128(encrypted_j0, ghash_block);
        
        expected_tag.resize(16);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(expected_tag.data()), tag_block);
    } else {
        std::vector<uint8_t> encrypted_j0 = cipher(j0);
        expected_tag = xorVectors(encrypted_j0, ghash_result);
    }
    
    // 認証タグの検証
    if (received_tag != expected_tag) {
        throw std::runtime_error("GCM authentication failed");
    }
    
    // CTRモードで復号化
    return decryptGCM_ctr(encrypted_data, iv, 2);
}

// CTRモードでの暗号化（GCM用）
std::vector<uint8_t> AES::encryptGCM_ctr(const std::vector<uint8_t>& plainText, const std::vector<uint8_t>& iv, uint32_t counterStart) {
    if (plainText.empty()) return {};
    
    std::vector<uint8_t> result;
    result.reserve(plainText.size());
    
    uint32_t counter = counterStart;
    
    for (size_t i = 0; i < plainText.size(); i += 16) {
        // カウンターブロックの生成
        std::vector<uint8_t> counterBlock = generateCounterBlock(iv, counter++);
        
        // カウンターブロックを暗号化
        std::vector<uint8_t> encryptedCounter;
        if (aesniSupported) {
            __m128i cb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(counterBlock.data()));
            __m128i encrypted_cb = encryptBlock(cb);
            encryptedCounter.resize(16);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(encryptedCounter.data()), encrypted_cb);
        } else {
            encryptedCounter = cipher(counterBlock);
        }
        
        // 平文とXOR
        size_t bytes_to_process = std::min(static_cast<size_t>(16), plainText.size() - i);
        for (size_t j = 0; j < bytes_to_process; ++j) {
            result.push_back(plainText[i + j] ^ encryptedCounter[j]);
        }
    }
    
    return result;
}

// CTRモードでの復号化（GCM用）
std::vector<uint8_t> AES::decryptGCM_ctr(const std::vector<uint8_t>& cipherText, const std::vector<uint8_t>& iv, uint32_t counterStart) {
    // CTRモードでは暗号化と復号化は同じ操作
    return encryptGCM_ctr(cipherText, iv, counterStart);
}

// カウンターブロックの生成
std::vector<uint8_t> AES::generateCounterBlock(const std::vector<uint8_t>& iv, uint32_t counter) {
    std::vector<uint8_t> counterBlock = iv;  // IVをコピー（12バイト）
    
    // 32ビットカウンターを追加（ビッグエンディアン）
    counterBlock.push_back((counter >> 24) & 0xFF);
    counterBlock.push_back((counter >> 16) & 0xFF);
    counterBlock.push_back((counter >> 8) & 0xFF);
    counterBlock.push_back(counter & 0xFF);
    
    return counterBlock;
}

// GF(2^128)での乗算
std::vector<uint8_t> AES::gfMultiply(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y) {
    std::vector<uint8_t> result(16, 0);
    std::vector<uint8_t> v = y;
    
    for (int i = 0; i < 128; ++i) {
        // x の i番目のビットが1の場合
        if ((x[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; ++j) {
                result[j] ^= v[j];
            }
        }
        
        // v を左に1ビットシフト
        bool msb = (v[0] & 0x80) != 0;
        for (int j = 0; j < 15; ++j) {
            v[j] = (v[j] << 1) | ((v[j + 1] & 0x80) >> 7);
        }
        v[15] <<= 1;
        
        // MSBが1だった場合、還元多項式 0x87 でXOR
        if (msb) {
            v[15] ^= 0x87;
        }
    }
    
    return result;
}

// GHASH関数
std::vector<uint8_t> AES::ghash(const std::vector<uint8_t>& h, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> y(16, 0);
    
    for (size_t i = 0; i < data.size(); i += 16) {
        // データブロックを取得
        std::vector<uint8_t> block(data.begin() + i, data.begin() + i + 16);
        
        // Y_i = (Y_{i-1} ⊕ X_i) * H
        for (int j = 0; j < 16; ++j) {
            y[j] ^= block[j];
        }
        y = gfMultiply(y, h);
    }
    
    return y;
}

//----------AES-NI----------

// AES-NIを使用してCBCモードで暗号化
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
// 29p AES Encryption and Decryption in CBC Mode 
std::vector<uint8_t> AES::encryptAESNI_cbc(const std::vector<uint8_t>& plainText) {
    if (plainText.size() == 0) return {};

    // パディング追加 (PKCS#7)
    std::vector<uint8_t> padded = padInput(plainText);

    // IV生成
    std::vector<uint8_t> iv(ivSize);
    std::random_device rd;
    std::generate(iv.begin(), iv.end(), [&]() { return rd(); });

    __m128i ivBlock = _mm_loadu_si128(reinterpret_cast<__m128i*>(iv.data()));

    std::vector<uint8_t> cipher(iv.size() + padded.size());
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipher.data()), ivBlock);

    // CBC暗号化
    for (size_t i = 0; i < padded.size(); i += paddingSize) {
        __m128i plainBlock = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(padded.data() + i));

        ivBlock = _mm_xor_si128(plainBlock, ivBlock);
        ivBlock = encryptBlock(ivBlock);

        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(cipher.data() + iv.size() + i), ivBlock);
    }

    return cipher;
}

// AES-NIを使用してCBCモードで復号化
std::vector<uint8_t> AES::decryptAESNI_cbc(const std::vector<uint8_t>& cipherText) {
    if (cipherText.size() < ivSize || (cipherText.size() - ivSize) % Nb != 0) {
        throw std::invalid_argument("Invalid cipher length");
    }

    // IV抽出
    __m128i ivBlock = _mm_loadu_si128(reinterpret_cast<const __m128i*>(cipherText.data()));
    __m128i prevBlock = ivBlock;

    const size_t dataLen = cipherText.size() - ivSize;
    std::vector<uint8_t> plain(dataLen);

    // CBC復号
    for (size_t i = ivSize; i < cipherText.size(); i += paddingSize) {
        __m128i ct_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(cipherText.data() + i));

        __m128i pt_block = decryptBlock(ct_block);
        pt_block = _mm_xor_si128(pt_block, prevBlock);

        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(plain.data() + i - ivSize), pt_block);

        prevBlock = ct_block;
    }

    // パディング削除
    size_t padLen = plain.back();

    if (padLen > paddingSize) throw std::runtime_error("Invalid padding");

    plain.resize(plain.size() - padLen);
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
    std::vector<uint8_t> randomBytes(length);
    std::random_device rd;

    for (size_t i = 0; i < length; ++i) {
        randomBytes[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    return randomBytes;
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
    size_t paddingSize = 16 - (input.size() % 16);
    std::vector<uint8_t> padded = input;
    padded.insert(padded.end(), paddingSize, static_cast<uint8_t>(paddingSize));

    // デバッグ出力
    paddingPrintHex(padded, paddingSize);

    return padded;
}

// 復号したテキストからパディングを削除
// Remove padding from the decrypted text
std::vector<uint8_t> AES::removePadding(const std::vector<uint8_t>& paddedInput) {
    if (paddedInput.size() < 16) {
        throw std::invalid_argument("Padded input too short");
    }

    const uint8_t paddingValue = paddedInput.back();
    if (paddingValue == 0 || paddingValue > 16) {
        throw std::invalid_argument("Invalid padding value");
    }

    // 全パディングバイトをチェック
    const size_t paddingStart = paddedInput.size() - paddingValue;

    // デバッグ情報出力
#ifdef _DEBUG
    std::cerr << "Padding value detected: " << static_cast<int>(paddingValue)
        << "\nLast 16 bytes:\n";
    for (size_t i = (paddedInput.size() < 16) ? 0 : paddedInput.size() - 16;
        i < paddedInput.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)paddedInput[i];
        if ((i + 1) % 16 == 0) {
            std::cout << '\n';
        }
        else {
            std::cout << ' ';
        }
    }
    for (size_t i = paddingStart; i < paddedInput.size(); ++i) {
        if (paddedInput[i] != paddingValue) {
            throw std::invalid_argument("Padding byte mismatch");
        }
    }
    std::cout << std::dec;
#endif

    return std::vector<uint8_t>(
        paddedInput.begin(),
        paddedInput.begin() + paddingStart
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

void AES::paddingPrintHex(const std::vector<uint8_t> &data, const size_t& dataSize) const {
    #ifdef _DEBUG
        std::cout << "Padding added: " << static_cast<int>(dataSize) << " bytes\nPadded data:\n";
        for (size_t i = 0; i < data.size(); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
            if ((i + 1) % 16 == 0) {
                std::cout << '\n';
            }
            else {
                std::cout << ' ';
            }
        }
        std::cout << std::dec << std::endl;
    #endif
}
