#include "AES.h"

AES::AES(const std::vector<uint8_t>& cipherKey, const bool aesniflag) : key(cipherKey), aesniSupported(check_aesni_support(aesniflag))
{
    // 逆元テーブルの初期化
    initInverse();

    // Figure 4. Key-Block-Round Combination
    if (cipherKey.size() == AES_128) { // AES-128
        Nk = 4;
        Nr = 10;
    }
    else if (cipherKey.size() == AES_192) { // AES-192
        Nk = 6;
        Nr = 12;
    }
    else if (cipherKey.size() == AES_256) { // AES-256
        Nk = 8;
        Nr = 14;
    }
    else {
        // Handle error: cipher_key byte length must be 16, 24, or 32
    }

    // rd_keyとdec_keyのサイズを設定 (Nrはラウンド数なので Nr + 1 個の鍵が必要)
    rd_key.resize(Nr + 1);
    dec_key.resize(Nr + 1);

    // AES-NIがサポートされている場合
    if (aesniSupported) {
        // 鍵拡張
        __m128i temp1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
        __m128i temp2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + 16));
        rd_key[0] = temp1;
        rd_key[1] = temp2;

        for (size_t i = 2; i < Nr + 1; ++i) {
            __m128i keygened = _mm_aeskeygenassist_si128(temp2, 0x01);
            keygened = _mm_shuffle_epi32(keygened, 0xFF);

            temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
            temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
            temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
            temp1 = _mm_xor_si128(temp1, keygened);

            rd_key[i++] = temp1;

            if (i > Nr) break;

            __m128i temp3 = _mm_aeskeygenassist_si128(temp1, 0x00);
            temp3 = _mm_shuffle_epi32(temp3, 0xAA);

            temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
            temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
            temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
            temp2 = _mm_xor_si128(temp2, temp3);

            rd_key[i] = temp2;
        }

        // 復号用鍵生成
        dec_key[0] = rd_key[Nr];
        for (size_t i = 1; i < Nr; ++i) {
            dec_key[i] = _mm_aesimc_si128(rd_key[Nr - i]);
        }
        dec_key[Nr] = rd_key[0];
    }
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

std::vector<uint32_t> AES::keyExpansion(const std::vector<uint8_t>& key, uint8_t Nk, uint8_t Nb, uint8_t Nr) {
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
    for (int i = 0; i < 4; ++i) printf("%08x ", w[i]);
    std::cout << "\nLast round key: ";
    for (int i = w.size() - 4; i < w.size(); ++i) printf("%08x ", w[i]);
    std::cout << "\n";
#endif

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

    // デバッグ出力
#ifdef _DEBUG
    std::cout << "Padding added: " << static_cast<int>(padding_size)
        << " bytes\nPadded data:\n";
    for (size_t i = 0; i < padded.size(); ++i) {
        printf("%02x%c", padded[i], ((i + 1) % 16 == 0) ? '\n' : ' ');
    }
#endif
    return padded;
}

// 復号したテキストからパディングを削除
// Remove padding from the decrypted text
std::vector<uint8_t> AES::remove_padding(const std::vector<uint8_t>& padded_input) {
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
        printf("%02x%c", padded_input[i], ((i + 1) % 16 == 0) ? '\n' : ' ');
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

// CBCモードで暗号化
std::vector<uint8_t> AES::encrypt_cbc(const std::vector<uint8_t>& plain_text) {
    if (!aesniSupported) {
        std::vector<uint8_t> iv = generate_iv();
        std::vector<uint8_t> padded_text = pad_input(plain_text);
        std::vector<uint8_t> cipher_text = iv;

        std::vector<uint8_t> previous_block = iv;
        for (size_t i = 0; i < padded_text.size(); i += paddingSize) {
            std::vector<uint8_t> block(padded_text.begin() + i, padded_text.begin() + i + paddingSize);
            block = xor_vectors(block, previous_block);
            std::vector<uint8_t> encrypted_block = encrypt_block(block, key);
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
            std::vector<uint8_t> decrypted_block = decrypt_block(block, key);
            std::vector<uint8_t> plain_block = xor_vectors(decrypted_block, previous_block);
            plain_text.insert(plain_text.end(), plain_block.begin(), plain_block.end());
            previous_block = block;
        }

        return remove_padding(plain_text);
    }
    else {
        return decryptAESNI_cbc(cipher_text);
    }
}


#include <immintrin.h>
// AES-NIを使用して暗号化
std::vector<uint8_t> AES::encryptAESNI_cbc(const std::vector<uint8_t>& plain_text) {
    if (plain_text.size() == 0) return {};

    // パディング追加 (PKCS#7)
    size_t pad_len = paddingSize - (plain_text.size() % paddingSize);
    std::vector<uint8_t> padded(plain_text.begin(), plain_text.end());
    padded.resize(plain_text.size() + pad_len, static_cast<uint8_t>(pad_len));

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
        iv_block = encrypt_block(iv_block);

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

        __m128i pt_block = decrypt_block(ct_block);
        pt_block = _mm_xor_si128(pt_block, prev_block);

        _mm_storeu_si128(
            reinterpret_cast<__m128i*>(plain.data() + i - ivSize), pt_block);

        prev_block = ct_block;
    }

    // パディング削除
    size_t pad_len = plain.back();
    if (pad_len > Nb) throw std::runtime_error("Invalid padding");

    plain.resize(plain.size() - pad_len);
    return plain;
}

// AES-NIがCPUにあるのか判定するプログラム
// 引数のフラグは任意でAES-NIを使用するかのフラグで、
// trueの場合でもCPUがAES-NIをサポートしていない場合はfalseを返します
bool AES::check_aesni_support(const bool aesniflag) {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);

    // ECXレジスタの25ビット目がAES-NIのサポートを示します
    return ((cpuInfo[2] & (1 << 25)) != 0) && aesniflag;
}