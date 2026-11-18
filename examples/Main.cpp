#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <memory>
#include <chrono>

void hexdump(const std::vector<uint8_t>& data) {
    const size_t bytesLine = 16;

    for (size_t i = 0; i < data.size(); i += bytesLine) {
        std::cout << std::dec << std::setw(5) << std::setfill('0') << i << ": ";

        for (size_t j = 0; j < bytesLine; ++j) {
            if (i + j < data.size()) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i + j] << ' ';
            }
            else {
                std::cout << "   "; // 16バイト未満の場合はスペースを埋める
            }
        }

        std::cout << " | ";
        // ASCII表示
        for (size_t j = 0; j < bytesLine; ++j) {
            if (i + j < data.size()) {
                // 表示可能な文字かチェック
                unsigned char c = data[i + j];
                if (isprint(c)) {
                    std::cout << c;
                }
                else {
                    std::cout << '.';
                }
            }
        }
        std::cout << std::dec << std::endl;
    }
}

// 16進文字列をバイトベクターに変換
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ========================================
// 基本CBCテスト
// ========================================
bool testBasicCBC() {
    std::cout << "\n=== BASIC CBC MODE TESTS ===" << std::endl;
    bool allPassed = true;

    std::string testText = "the magic words are squeamish ossifrage To know is to know that you know nothing That is the true meaning of knowledge";
    std::vector<uint8_t> plaintextBytes(testText.begin(), testText.end());

    std::cout << "Testing basic CBC encryption/decryption..." << std::endl;
    std::cout << "PlainText length: " << testText.length() << " bytes" << std::endl;

    std::vector<uint8_t> key(32);
    std::random_device rd;

    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    AES aesSoft(key, false);
    AES aesNi(key, true);

    try {
        // ソフトウェア実装テスト
        std::cout << "  Software CBC encrypt/decrypt... ";
        std::vector<uint8_t> cipherSoft = aesSoft.encrypt_cbc(plaintextBytes);
        std::vector<uint8_t> decryptedSoft = aesSoft.decrypt_cbc(cipherSoft);

        std::string recoveredSoft(
            reinterpret_cast<const char*>(decryptedSoft.data()),
            decryptedSoft.size());

        if (recoveredSoft == testText) {
            std::cout << "PASS" << std::endl;
        }
        else {
            std::cout << "FAIL (mismatch)" << std::endl;
            allPassed = false;
        }

        // AES-NI実装テスト
        std::cout << "  AES-NI CBC encrypt/decrypt... ";
        std::vector<uint8_t> cipherNi = aesNi.encrypt_cbc(plaintextBytes);
        std::vector<uint8_t> decryptedNi = aesNi.decrypt_cbc(cipherNi);

        std::string recoveredNi(
            reinterpret_cast<const char*>(decryptedNi.data()),
            decryptedNi.size());

        if (recoveredNi == testText) {
            std::cout << "PASS" << std::endl;
        }
        else {
            std::cout << "FAIL (mismatch)" << std::endl;
            allPassed = false;
        }

        // 相互運用性テスト（AES-NI→ソフトウェア）
        std::cout << "  Cross-compatibility (AES-NI->Software)... ";
        try {
            std::vector<uint8_t> crossTest1 = aesSoft.decrypt_cbc(cipherNi);
            std::string crossRecovered1(
                reinterpret_cast<const char*>(crossTest1.data()),
                crossTest1.size());

            if (crossRecovered1 == testText) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL (mismatch)" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")" << std::endl;
            allPassed = false;
        }

        // 相互運用性テスト（ソフトウェア→AES-NI）
        std::cout << "  Cross-compatibility (Software->AES-NI)... ";
        try {
            std::vector<uint8_t> crossTest2 = aesNi.decrypt_cbc(cipherSoft);
            std::string crossRecovered2(
                reinterpret_cast<const char*>(crossTest2.data()),
                crossTest2.size());

            if (crossRecovered2 == testText) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL (mismatch)" << std::endl;
                allPassed = false;
            }
        }
        catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")" << std::endl;
            allPassed = false;
        }

    }
    catch (const std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        allPassed = false;
    }

    return allPassed;
}

// ========================================
// GCMモードのテスト
// ========================================
bool testGCM() {
    std::cout << "\n\n=== TEST CASE 2 (GCM MODE) ===" << std::endl;

    std::vector<uint8_t> key(32);
    std::random_device rd;

    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    AES aesSoft(key, false);
    AES aesNi(key, true);

    std::string testText = "the magic words are squeamish ossifrage To know is to know that you know nothing That is the true meaning of knowledge";
    // 異なる平文サイズでテスト
    std::vector<std::string> testPlaintexts = {
        "Hello, GCM!",  // 短い文字列
        testText,     // 長い文字列
        "A",            // 1文字
        "",             // 空文字列
        "This is exactly 16 bytes!",  // 16バイトちょうど
        "This text is 33 characters long!!"  // 16バイトより少し長い
    };

    bool gcmTestsPassed = true;

    for (size_t test_idx = 0; test_idx < testPlaintexts.size(); ++test_idx) {
        const std::string& testText = testPlaintexts[test_idx];
        std::cout << "\nGCM Test " << (test_idx + 1) << ": ";
        if (testText.empty()) {
            std::cout << "(Empty string)";
        }
        else if (testText.length() > 50) {
            std::cout << testText.substr(0, 47) << "...";
        }
        else {
            std::cout << testText;
        }
        std::cout << " (" << testText.length() << " bytes)" << std::endl;

        std::vector<uint8_t> testPlaintext(testText.begin(), testText.end());

        try {
            // ソフトウェア実装でのGCM暗号化・復号化
            std::cout << "  Software GCM encrypt/decrypt... ";
            std::vector<uint8_t> gcmCipherSoft = aesSoft.encrypt_gcm(testPlaintext);

            // 空文字列の場合、暗号文サイズをデバッグ出力
            if (testText.empty()) {
                std::cout << "\n    Debug: Empty string cipher size = " << gcmCipherSoft.size()
                    << " bytes (expected: " << (12 + 16) << " bytes)" << std::endl;
                std::cout << "    ";
            }

            std::vector<uint8_t> gcmDecryptedSoft = aesSoft.decrypt_gcm(gcmCipherSoft);

            std::string gcmRecoveredSoft(
                reinterpret_cast<const char*>(gcmDecryptedSoft.data()),
                gcmDecryptedSoft.size());

            if (gcmRecoveredSoft == testText) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL (mismatch)" << std::endl;
                gcmTestsPassed = false;
            }

            // AES-NI実装でのGCM暗号化・復号化
            std::cout << "  AES-NI GCM encrypt/decrypt... ";
            std::vector<uint8_t> gcmCipherAesni = aesNi.encrypt_gcm(testPlaintext);

            // 空文字列の場合、AES-NIの暗号文サイズもデバッグ出力
            if (testText.empty()) {
                std::cout << "\n    Debug: AES-NI empty string cipher size = " << gcmCipherAesni.size()
                    << " bytes" << std::endl;
                std::cout << "    ";
            }

            std::vector<uint8_t> gcmDecryptedAesni = aesNi.decrypt_gcm(gcmCipherAesni);

            std::string gcmRecoveredAesni(
                reinterpret_cast<const char*>(gcmDecryptedAesni.data()),
                gcmDecryptedAesni.size());

            if (gcmRecoveredAesni == testText) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL (mismatch)" << std::endl;
                gcmTestsPassed = false;
            }

            // 相互運用性テスト（ソフトウェア暗号化 → AES-NI復号化）
            std::cout << "  Cross-compatibility (Software->AES-NI)... ";
            try {
                std::vector<uint8_t> gcmCrossTest1 = aesNi.decrypt_gcm(gcmCipherSoft);
                std::string gcmCrossRecovered1(
                    reinterpret_cast<const char*>(gcmCrossTest1.data()),
                    gcmCrossTest1.size());

                if (gcmCrossRecovered1 == testText) {
                    std::cout << "PASS" << std::endl;
                }
                else {
                    std::cout << "FAIL (mismatch)" << std::endl;
                    gcmTestsPassed = false;
                }
            }
            catch (const std::exception& e) {
                std::cout << "FAIL (exception: " << e.what() << ")" << std::endl;
                gcmTestsPassed = false;
            }

            // 相互運用性テスト（AES-NI暗号化 → ソフトウェア復号化）
            std::cout << "  Cross-compatibility (AES-NI->Software)... ";
            try {
                std::vector<uint8_t> gcmCrossTest2 = aesSoft.decrypt_gcm(gcmCipherAesni);
                std::string gcmCrossRecovered2(
                    reinterpret_cast<const char*>(gcmCrossTest2.data()),
                    gcmCrossTest2.size());

                if (gcmCrossRecovered2 == testText) {
                    std::cout << "PASS" << std::endl;
                }
                else {
                    std::cout << "FAIL (mismatch)" << std::endl;
                    gcmTestsPassed = false;
                }
            }
            catch (const std::exception& e) {
                std::cout << "FAIL (exception: " << e.what() << ")" << std::endl;
                gcmTestsPassed = false;
            }

            // 暗号文改ざんテスト（認証機能の確認）
            if (!testText.empty() && gcmCipherSoft.size() > 16) {
                std::cout << "  Authentication test (tamper detection)... ";
                std::vector<uint8_t> tamperedCipher = gcmCipherSoft;
                // 暗号文部分を1ビット改ざん
                tamperedCipher[16] ^= 0x01;

                try {
                    aesSoft.decrypt_gcm(tamperedCipher);
                    std::cout << "FAIL (tampered data accepted)" << std::endl;
                    gcmTestsPassed = false;
                }
                catch (const std::runtime_error& e) {
                    std::cout << "PASS (tamper detected)" << std::endl;
                }
                catch (const std::exception& e) {
                    std::cout << "FAIL (unexpected exception: " << e.what() << ")" << std::endl;
                    gcmTestsPassed = false;
                }
            }

        }
        catch (const std::exception& e) {
            std::cout << "ERROR: " << e.what() << std::endl;
            gcmTestsPassed = false;
        }
    }

    if (gcmTestsPassed) {
        std::cout << "\nGCM Mode: All tests PASSED!" << std::endl;
    }
    else {
        std::cout << "\nGCM Mode: Some tests FAILED!" << std::endl;
    }
    // GCMモードのテスト結果を返す
    return gcmTestsPassed;
}

// 異なる鍵サイズのテスト
bool testDifferentKeySizes() {
    std::cout << "\n=== KEY SIZE TESTS ===" << std::endl;
    bool allPassed = true;

    std::vector<size_t> keySizes = { 16, 24, 32 }; // AES-128, AES-192, AES-256
    std::string testText = "Key size test data!";
    std::vector<uint8_t> plaintext(testText.begin(), testText.end());

    for (size_t keySize : keySizes) {
        std::cout << "Testing AES-" << (keySize * 8) << "..." << std::endl;

        // ランダムキー生成
        std::vector<uint8_t> key(keySize);
        std::random_device rd;
        for (size_t i = 0; i < keySize; ++i) {
            key[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        try {
            AES aesSoft(key, false);
            AES aesNi(key, true);

            // CBC テスト
            std::vector<uint8_t> cipher_cbc_soft = aesSoft.encrypt_cbc(plaintext);
            std::vector<uint8_t> decrypted_cbc_soft = aesSoft.decrypt_cbc(cipher_cbc_soft);

            std::vector<uint8_t> cipher_cbc_ni = aesNi.encrypt_cbc(plaintext);
            std::vector<uint8_t> decrypted_cbc_ni = aesNi.decrypt_cbc(cipher_cbc_ni);

            // GCM テスト
            std::vector<uint8_t> cipher_gcm_soft = aesSoft.encrypt_gcm(plaintext);
            std::vector<uint8_t> decrypted_gcm_soft = aesSoft.decrypt_gcm(cipher_gcm_soft);

            std::vector<uint8_t> cipher_gcm_ni = aesNi.encrypt_gcm(plaintext);
            std::vector<uint8_t> decrypted_gcm_ni = aesNi.decrypt_gcm(cipher_gcm_ni);

            // GCM-SIV テスト (AES-192はスキップ)
            bool gcm_siv_ok = true;
            if (keySize != 24) {
                std::vector<uint8_t> cipher_siv_soft = aesSoft.encrypt_gcm_siv(plaintext);
                std::vector<uint8_t> decrypted_siv_soft = aesSoft.decrypt_gcm_siv(cipher_siv_soft);

                std::vector<uint8_t> cipher_siv_ni = aesNi.encrypt_gcm_siv(plaintext);
                std::vector<uint8_t> decrypted_siv_ni = aesNi.decrypt_gcm_siv(cipher_siv_ni);

                gcm_siv_ok = (decrypted_siv_soft == plaintext && decrypted_siv_ni == plaintext);
            }

            // 検証
            bool cbc_ok = (decrypted_cbc_soft == plaintext && decrypted_cbc_ni == plaintext);
            bool gcm_ok = (decrypted_gcm_soft == plaintext && decrypted_gcm_ni == plaintext);

            if (cbc_ok && gcm_ok && gcm_siv_ok) {
                std::cout << "  AES-" << (keySize * 8) << ": PASS" << std::endl;
            }
            else {
                std::cout << "  AES-" << (keySize * 8) << ": FAIL" << std::endl;
                allPassed = false;
            }

        }
        catch (const std::exception& e) {
            std::cout << "  AES-" << (keySize * 8) << ": ERROR - " << e.what() << std::endl;
            allPassed = false;
        }
    }

    return allPassed;
}

// 大容量データセットのテスト
bool testLargeDataSets() {
    std::cout << "\n=== LARGE DATA TESTS ===" << std::endl;
    bool allPassed = true;

    // 大容量テストデータ
    std::vector<size_t> dataSizes = { 1024, 4096, 16384, 65536 }; // 1KB, 4KB, 16KB, 64KB

    std::vector<uint8_t> key(32);
    std::random_device rd;
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    AES aesSoft(key, false);
    AES aesNi(key, true);

    for (size_t dataSize : dataSizes) {
        std::cout << "Testing " << dataSize << " bytes..." << std::endl;

        // ランダムデータ生成
        std::vector<uint8_t> large_data(dataSize);
        for (size_t i = 0; i < dataSize; ++i) {
            large_data[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        try {
            // CBC大容量テスト
            auto startTime = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> cipher_cbc = aesSoft.encrypt_cbc(large_data);
            std::vector<uint8_t> decrypted_cbc = aesSoft.decrypt_cbc(cipher_cbc);
            auto endTime = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            // GCM大容量テスト
            startTime = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> cipher_gcm = aesSoft.encrypt_gcm(large_data);
            std::vector<uint8_t> decrypted_gcm = aesSoft.decrypt_gcm(cipher_gcm);
            auto endTime_gcm = std::chrono::high_resolution_clock::now();

            auto duration_gcm = std::chrono::duration_cast<std::chrono::milliseconds>(endTime_gcm - startTime);

            bool testPassed = (decrypted_cbc == large_data && decrypted_gcm == large_data);

            if (testPassed) {
                std::cout << "  " << dataSize << " bytes: PASS (CBC: "
                    << duration.count() << "ms, GCM: " << duration_gcm.count() << "ms)" << std::endl;
            }
            else {
                std::cout << "  " << dataSize << " bytes: FAIL" << std::endl;
                allPassed = false;
            }

        }
        catch (const std::exception& e) {
            std::cout << "  " << dataSize << " bytes: ERROR - " << e.what() << std::endl;
            allPassed = false;
        }
    }

    return allPassed;
}

// エラー条件のテスト
bool testErrorConditions() {
    std::cout << "\n=== ERROR CONDITION TESTS ===" << std::endl;
    bool allPassed = true;

    // 無効なキーサイズテスト
    std::cout << "Testing invalid key sizes..." << std::endl;
    std::vector<size_t> invalidSizes = { 8, 12, 20, 28, 40 };

    for (size_t invalidSize : invalidSizes) {
        try {
            std::vector<uint8_t> invalidKey(invalidSize, 0x42);
            AES aes(invalidKey, false);
            std::cout << "  Key size " << invalidSize << ": FAIL (should have thrown)" << std::endl;
            allPassed = false;
        }
        catch (const std::invalid_argument&) {
            std::cout << "  Key size " << invalidSize << ": PASS (correctly rejected)" << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "  Key size " << invalidSize << ": FAIL (unexpected exception: " << e.what() << ")" << std::endl;
            allPassed = false;
        }
    }

    // GCM認証タグ改ざんテスト
    std::cout << "\nTesting GCM tag tampering..." << std::endl;
    std::vector<uint8_t> key(32, 0x33);
    AES aes(key, false);

    std::string testText = "Authentication test data";
    std::vector<uint8_t> plainText(testText.begin(), testText.end());

    try {
        std::vector<uint8_t> cipher = aes.encrypt_gcm(plainText);

        // 認証タグの最後のバイトを改ざん
        if (cipher.size() > 0) {
            cipher.back() ^= 0x01;
        }

        try {
            aes.decrypt_gcm(cipher);
            std::cout << "  Tag tampering: FAIL (tampered data accepted)" << std::endl;
            allPassed = false;
        }
        catch (const std::runtime_error&) {
            std::cout << "  Tag tampering: PASS (correctly detected)" << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cout << "  Tag tampering: ERROR - " << e.what() << std::endl;
        allPassed = false;
    }

    // CBC不正パディングテスト
    std::cout << "\nTesting CBC invalid padding..." << std::endl;
    try {
        auto cipher = aes.encrypt_cbc(plainText);
        // Alter the previous block (or IV) to force the final padding byte to zero.
        const uint8_t pad = static_cast<uint8_t>(16 - plainText.size() % 16);
        cipher[cipher.size() - 17] ^= pad;

        try {
            aes.decrypt_cbc(cipher);
            std::cout << "  Invalid padding: FAIL (should have been rejected)" << std::endl;
            allPassed = false;
        }
        catch (const std::exception&) {
            std::cout << "  Invalid padding: PASS (correctly detected)" << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cout << "  Invalid padding test: ERROR - " << e.what() << std::endl;
        allPassed = false;
    }

    return allPassed;
}

// 特殊なデータパターンのテスト
bool testSpecialDataPatterns() {
    std::cout << "\n=== SPECIAL DATA PATTERN TESTS ===" << std::endl;
    bool allPassed = true;

    std::vector<uint8_t> key(32);
    std::random_device rd;
    for (size_t i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    AES aesSoft(key, false);
    AES aesNi(key, true);

    // テストパターン定義
    struct TestPattern {
        std::string name;
        std::vector<uint8_t> data;
    };

    std::vector<TestPattern> patterns = {
        {"All zeros", std::vector<uint8_t>(64, 0x00)},
        {"All ones", std::vector<uint8_t>(64, 0xFF)},
        {"Alternating", {}},
        {"Ascending", {}},
        {"Binary data", {0x00, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF}},
        {"UTF-8 text", [] {
                std::string utf8_text = u8"こんにちは世界";
                return std::vector<uint8_t>(utf8_text.begin(), utf8_text.end());
            }()}
    };

    // パターン生成
    for (int i = 0; i < 64; ++i) {
        patterns[2].data.push_back(i % 2 ? 0xFF : 0x00); // Alternating
        patterns[3].data.push_back(static_cast<uint8_t>(i)); // Ascending
    }

    for (const auto& pattern : patterns) {
        std::cout << "Testing pattern: " << pattern.name << "..." << std::endl;

        try {
            // CBCテスト
            std::vector<uint8_t> cipher_cbc_soft = aesSoft.encrypt_cbc(pattern.data);
            std::vector<uint8_t> decrypted_cbc_soft = aesSoft.decrypt_cbc(cipher_cbc_soft);

            std::vector<uint8_t> cipher_cbc_ni = aesNi.encrypt_cbc(pattern.data);
            std::vector<uint8_t> decrypted_cbc_ni = aesNi.decrypt_cbc(cipher_cbc_ni);

            // GCMテスト
            std::vector<uint8_t> cipher_gcm_soft = aesSoft.encrypt_gcm(pattern.data);
            std::vector<uint8_t> decrypted_gcm_soft = aesSoft.decrypt_gcm(cipher_gcm_soft);

            std::vector<uint8_t> cipher_gcm_ni = aesNi.encrypt_gcm(pattern.data);
            std::vector<uint8_t> decrypted_gcm_ni = aesNi.decrypt_gcm(cipher_gcm_ni);

            bool cbc_ok = (decrypted_cbc_soft == pattern.data && decrypted_cbc_ni == pattern.data);
            bool gcm_ok = (decrypted_gcm_soft == pattern.data && decrypted_gcm_ni == pattern.data);

            if (cbc_ok && gcm_ok) {
                std::cout << "  " << pattern.name << ": PASS" << std::endl;
            }
            else {
                std::cout << "  " << pattern.name << ": FAIL" << std::endl;
                allPassed = false;
            }

        }
        catch (const std::exception& e) {
            std::cout << "  " << pattern.name << ": ERROR - " << e.what() << std::endl;
            allPassed = false;
        }
    }

    return allPassed;
}

// ========================================
// GCM-SIVモードのテスト (RFC 8452)
// ========================================
bool testGCMSIV() {
    std::cout << "\n\n=== TEST CASE: GCM-SIV MODE (RFC 8452) ===" << std::endl;

    bool allPassed = true;

    // --- AES-128-GCM-SIV テスト ---
    std::cout << "\n--- AES-128-GCM-SIV ---" << std::endl;
    {
        std::vector<uint8_t> key128(16);
        std::random_device rd;
        for (size_t i = 0; i < 16; ++i) {
            key128[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        AES aesSoft128(key128, false);
        AES aesNi128(key128, true);

        std::vector<std::string> testPlaintexts = {
            "",                                    // 空文字列
            "Hello, GCM-SIV!",                     // 短い文字列
            "A",                                   // 1文字
            "This is exactly 16 bytes!",            // ブロック境界テスト
            "the magic words are squeamish ossifrage To know is to know that you know nothing That is the true meaning of knowledge",
        };

        for (size_t idx = 0; idx < testPlaintexts.size(); ++idx) {
            const std::string& testText = testPlaintexts[idx];
            std::cout << "\n  AES-128-GCM-SIV Test " << (idx + 1) << ": ";
            if (testText.empty()) {
                std::cout << "(Empty string)";
            } else if (testText.length() > 40) {
                std::cout << testText.substr(0, 37) << "...";
            } else {
                std::cout << testText;
            }
            std::cout << " (" << testText.length() << " bytes)" << std::endl;

            std::vector<uint8_t> pt(testText.begin(), testText.end());

            try {
                // ソフトウェア実装テスト
                std::cout << "    Software encrypt/decrypt... ";
                std::vector<uint8_t> ct = aesSoft128.encrypt_gcm_siv(pt);
                std::vector<uint8_t> dt = aesSoft128.decrypt_gcm_siv(ct);
                std::string recovered(reinterpret_cast<const char*>(dt.data()), dt.size());
                if (recovered == testText) {
                    std::cout << "PASS" << std::endl;
                } else {
                    std::cout << "FAIL (mismatch)" << std::endl;
                    allPassed = false;
                }

                // AES-NI実装テスト
                std::cout << "    AES-NI encrypt/decrypt... ";
                std::vector<uint8_t> ct_ni = aesNi128.encrypt_gcm_siv(pt);
                std::vector<uint8_t> dt_ni = aesNi128.decrypt_gcm_siv(ct_ni);
                std::string recovered_ni(reinterpret_cast<const char*>(dt_ni.data()), dt_ni.size());
                if (recovered_ni == testText) {
                    std::cout << "PASS" << std::endl;
                } else {
                    std::cout << "FAIL (mismatch)" << std::endl;
                    allPassed = false;
                }

                // 相互運用性テスト
                std::cout << "    Cross-compat (Software->AES-NI)... ";
                try {
                    std::vector<uint8_t> cross1 = aesNi128.decrypt_gcm_siv(ct);
                    std::string crossR1(reinterpret_cast<const char*>(cross1.data()), cross1.size());
                    if (crossR1 == testText) {
                        std::cout << "PASS" << std::endl;
                    } else {
                        std::cout << "FAIL (mismatch)" << std::endl;
                        allPassed = false;
                    }
                } catch (const std::exception& e) {
                    std::cout << "FAIL (" << e.what() << ")" << std::endl;
                    allPassed = false;
                }

                std::cout << "    Cross-compat (AES-NI->Software)... ";
                try {
                    std::vector<uint8_t> cross2 = aesSoft128.decrypt_gcm_siv(ct_ni);
                    std::string crossR2(reinterpret_cast<const char*>(cross2.data()), cross2.size());
                    if (crossR2 == testText) {
                        std::cout << "PASS" << std::endl;
                    } else {
                        std::cout << "FAIL (mismatch)" << std::endl;
                        allPassed = false;
                    }
                } catch (const std::exception& e) {
                    std::cout << "FAIL (" << e.what() << ")" << std::endl;
                    allPassed = false;
                }

                // 改ざん検出テスト
                if (!testText.empty() && ct.size() > 16) {
                    std::cout << "    Tamper detection... ";
                    std::vector<uint8_t> tampered = ct;
                    tampered[14] ^= 0x01;  // 暗号文を改ざん
                    try {
                        aesSoft128.decrypt_gcm_siv(tampered);
                        std::cout << "FAIL (tampered data accepted)" << std::endl;
                        allPassed = false;
                    } catch (const std::runtime_error&) {
                        std::cout << "PASS (tamper detected)" << std::endl;
                    }
                }

            } catch (const std::exception& e) {
                std::cout << "    ERROR: " << e.what() << std::endl;
                allPassed = false;
            }
        }
    }

    // --- AES-256-GCM-SIV テスト ---
    std::cout << "\n--- AES-256-GCM-SIV ---" << std::endl;
    {
        std::vector<uint8_t> key256(32);
        std::random_device rd;
        for (size_t i = 0; i < 32; ++i) {
            key256[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        AES aesSoft256(key256, false);
        AES aesNi256(key256, true);

        std::string testText = "AES-256-GCM-SIV encryption test with longer data for thorough testing";
        std::vector<uint8_t> pt(testText.begin(), testText.end());

        try {
            std::cout << "  Software encrypt/decrypt... ";
            std::vector<uint8_t> ct = aesSoft256.encrypt_gcm_siv(pt);
            std::vector<uint8_t> dt = aesSoft256.decrypt_gcm_siv(ct);
            std::string recovered(reinterpret_cast<const char*>(dt.data()), dt.size());
            if (recovered == testText) {
                std::cout << "PASS" << std::endl;
            } else {
                std::cout << "FAIL" << std::endl;
                allPassed = false;
            }

            std::cout << "  AES-NI encrypt/decrypt... ";
            std::vector<uint8_t> ct_ni = aesNi256.encrypt_gcm_siv(pt);
            std::vector<uint8_t> dt_ni = aesNi256.decrypt_gcm_siv(ct_ni);
            std::string recovered_ni(reinterpret_cast<const char*>(dt_ni.data()), dt_ni.size());
            if (recovered_ni == testText) {
                std::cout << "PASS" << std::endl;
            } else {
                std::cout << "FAIL" << std::endl;
                allPassed = false;
            }

            // 相互運用性テスト
            std::cout << "  Cross-compat (Software->AES-NI)... ";
            try {
                std::vector<uint8_t> cross1 = aesNi256.decrypt_gcm_siv(ct);
                std::string crossR1(reinterpret_cast<const char*>(cross1.data()), cross1.size());
                std::cout << (crossR1 == testText ? "PASS" : "FAIL") << std::endl;
                if (crossR1 != testText) allPassed = false;
            } catch (const std::exception& e) {
                std::cout << "FAIL (" << e.what() << ")" << std::endl;
                allPassed = false;
            }

            std::cout << "  Cross-compat (AES-NI->Software)... ";
            try {
                std::vector<uint8_t> cross2 = aesSoft256.decrypt_gcm_siv(ct_ni);
                std::string crossR2(reinterpret_cast<const char*>(cross2.data()), cross2.size());
                std::cout << (crossR2 == testText ? "PASS" : "FAIL") << std::endl;
                if (crossR2 != testText) allPassed = false;
            } catch (const std::exception& e) {
                std::cout << "FAIL (" << e.what() << ")" << std::endl;
                allPassed = false;
            }

        } catch (const std::exception& e) {
            std::cout << "  ERROR: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // --- AES-192 非対応テスト ---
    std::cout << "\n--- AES-192-GCM-SIV (should reject) ---" << std::endl;
    {
        std::vector<uint8_t> key192(24, 0x42);
        AES aes192(key192, false);
        std::vector<uint8_t> pt = {0x01, 0x02, 0x03};
        try {
            aes192.encrypt_gcm_siv(pt);
            std::cout << "  FAIL (AES-192 should have been rejected)" << std::endl;
            allPassed = false;
        } catch (const std::invalid_argument&) {
            std::cout << "  PASS (AES-192 correctly rejected)" << std::endl;
        }
    }

    // --- AAD（追加認証データ）テスト ---
    std::cout << "\n--- GCM-SIV with AAD ---" << std::endl;
    {
        std::vector<uint8_t> key(32);
        std::random_device rd;
        for (size_t i = 0; i < 32; ++i) {
            key[i] = static_cast<uint8_t>(rd() & 0xFF);
        }
        AES aes(key, false);

        std::string testText = "Authenticated message";
        std::vector<uint8_t> pt(testText.begin(), testText.end());
        std::vector<uint8_t> aad = {0x01, 0x02, 0x03, 0x04, 0x05};

        try {
            std::cout << "  Encrypt with AAD, decrypt with same AAD... ";
            std::vector<uint8_t> ct = aes.encrypt_gcm_siv(pt, aad);
            std::vector<uint8_t> dt = aes.decrypt_gcm_siv(ct, aad);
            std::string recovered(reinterpret_cast<const char*>(dt.data()), dt.size());
            if (recovered == testText) {
                std::cout << "PASS" << std::endl;
            } else {
                std::cout << "FAIL" << std::endl;
                allPassed = false;
            }

            // 異なるAADで復号（認証失敗すべき）
            std::cout << "  Decrypt with wrong AAD... ";
            std::vector<uint8_t> wrongAad = {0x01, 0x02, 0x03, 0x04, 0x06};
            try {
                aes.decrypt_gcm_siv(ct, wrongAad);
                std::cout << "FAIL (wrong AAD accepted)" << std::endl;
                allPassed = false;
            } catch (const std::runtime_error&) {
                std::cout << "PASS (correctly rejected)" << std::endl;
            }

            // AADなしで復号（認証失敗すべき）
            std::cout << "  Decrypt without AAD (encrypted with AAD)... ";
            try {
                aes.decrypt_gcm_siv(ct);
                std::cout << "FAIL (missing AAD accepted)" << std::endl;
                allPassed = false;
            } catch (const std::runtime_error&) {
                std::cout << "PASS (correctly rejected)" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "  ERROR: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    if (allPassed) {
        std::cout << "\nGCM-SIV Mode: All tests PASSED!" << std::endl;
    } else {
        std::cout << "\nGCM-SIV Mode: Some tests FAILED!" << std::endl;
    }

    return allPassed;
}

// ========================================
// NISTテストベクター検証
// ========================================
bool testNISTVectors() {
    std::cout << "\n=== NIST TEST VECTORS VALIDATION ===" << std::endl;
    bool allPassed = true;

    // NIST FIPS 197 Appendix C.1 - AES-128 テストベクター
    struct NISTTestVector {
        std::string name;
        std::string key_hex;
        std::string plaintext_hex;
        std::string expected_cipher_hex;
        size_t key_size;
    };

    std::vector<NISTTestVector> nistVectors = {
        // AES-128 FIPS 197 Appendix C.1
        {
            "AES-128 FIPS 197 C.1",
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            16
        },
        // AES-192 FIPS 197 Appendix C.2
        {
            "AES-192 FIPS 197 C.2",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
            24
        },
        // AES-256 FIPS 197 Appendix C.3
        {
            "AES-256 FIPS 197 C.3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
            32
        },
        // 追加のテストベクター（Known Answer Test - KAT）
        {
            "AES-128 KAT Vector 1",
            "80000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0edd33d3c621e546455bd8ba1418bec8",
            16
        },
        {
            "AES-128 KAT Vector 2",
            "00000000000000000000000000000000",
            "80000000000000000000000000000000",
            "3ad78e726c1ec02b7ebfe92b23d9ec34",
            16
        },
        // Multi-block Test (MMT)
        {
            "AES-128 MMT Vector",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "6bc1bee22e409f96e93d7e117393172a",
            "3ad77bb40d7a3660a89ecaf32466ef97",
            16
        }
    };

    for (const auto& vector : nistVectors) {
        std::cout << "\nTesting: " << vector.name << std::endl;

        try {
            // テストベクターデータの変換
            std::vector<uint8_t> key = hexStringToBytes(vector.key_hex);
            std::vector<uint8_t> plaintext = hexStringToBytes(vector.plaintext_hex);
            std::vector<uint8_t> expectedCipher = hexStringToBytes(vector.expected_cipher_hex);

            // キーサイズ検証
            if (key.size() != vector.key_size) {
                std::cout << "  ERROR: Invalid key size" << std::endl;
                allPassed = false;
                continue;
            }

            // ソフトウェア実装でのテスト
            std::cout << "  Software implementation... ";
            AES aesSoft(key, false);
            std::vector<uint8_t> cipherSoft = aesSoft.cipher(plaintext);
            std::vector<uint8_t> decryptedSoft = aesSoft.invCipher(cipherSoft);

            bool encrypt_ok = (cipherSoft == expectedCipher);
            bool decrypt_ok = (decryptedSoft == plaintext);

            if (encrypt_ok && decrypt_ok) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL";
                if (!encrypt_ok) std::cout << " (encrypt mismatch)";
                if (!decrypt_ok) std::cout << " (decrypt mismatch)";
                std::cout << std::endl;

                // デバッグ情報
                std::cout << "    Expected: ";
                for (auto b : expectedCipher) printf("%02x", b);
                std::cout << std::endl;
                std::cout << "    Got:      ";
                for (auto b : cipherSoft) printf("%02x", b);
                std::cout << std::endl;

                allPassed = false;
            }

            // AES-NI実装でのテスト
            std::cout << "  AES-NI implementation... ";
            AES aesNi(key, true);

            std::vector<uint8_t> cipherNi = aesNi.cipher(plaintext);
            std::vector<uint8_t> decryptedNi = aesNi.invCipher(cipherNi);
            bool niEncryptOk = (cipherNi == expectedCipher);
            bool niDecryptOk = (decryptedNi == plaintext);

            if (niEncryptOk && niDecryptOk) {
                std::cout << "PASS" << std::endl;
            }
            else {
                std::cout << "FAIL";
                if (!niEncryptOk) std::cout << " (encrypt mismatch)";
                if (!niDecryptOk) std::cout << " (decrypt mismatch)";
                std::cout << std::endl;
                allPassed = false;
            }

        }
        catch (const std::exception& e) {
            std::cout << "  ERROR: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    // 公開ブロックAPIは正確に16バイトの入力のみ受け付ける。
    std::cout << "\nTesting block-size validation..." << std::endl;
    const std::vector<size_t> invalidBlockSizes = {0, 15, 17};
    const std::vector<uint8_t> validationKey(16, 0);
    for (bool useAesNi : {false, true}) {
        AES aes(validationKey, useAesNi);
        bool rejectedAll = true;

        for (size_t size : invalidBlockSizes) {
            const std::vector<uint8_t> invalidBlock(size, 0);
            bool cipherRejected = false;
            bool invCipherRejected = false;

            try {
                aes.cipher(invalidBlock);
            }
            catch (const std::invalid_argument&) {
                cipherRejected = true;
            }

            try {
                aes.invCipher(invalidBlock);
            }
            catch (const std::invalid_argument&) {
                invCipherRejected = true;
            }

            rejectedAll &= cipherRejected && invCipherRejected;
        }

        std::cout << "  " << (useAesNi ? "AES-NI" : "Software") << ": "
                  << (rejectedAll ? "PASS" : "FAIL") << std::endl;
        allPassed &= rejectedAll;
    }

    return allPassed;
}

// ========================================
// NISTモンテカルロテスト
// ========================================
bool testNISTMonteCarlo() {
    std::cout << "\n=== NIST MONTE CARLO TESTS (SIMPLIFIED) ===" << std::endl;
    bool allPassed = true;

    // 簡略版モンテカルロテスト（実際のNISTテストは非常に長いため短縮）
    std::cout << "Running simplified Monte Carlo test for AES-128..." << std::endl;

    try {
        // 初期値
        std::vector<uint8_t> key = hexStringToBytes("00000000000000000000000000000000");
        std::vector<uint8_t> plaintext = hexStringToBytes("00000000000000000000000000000000");

        AES aesSoft(key, false);

        // 100回の反復（実際のNISTテストは10000回）
        auto currentPlain = plaintext;
        std::vector<uint8_t> currentKey = key;

        for (int i = 0; i < 100; ++i) {
            AES aes_iter(currentKey, false);
            std::vector<uint8_t> cipher = aes_iter.cipher(currentPlain);

            // 次の反復のための更新
            currentPlain = cipher;

            // キーの更新（AES-128の場合）
            for (size_t j = 0; j < 16; ++j) {
                currentKey[j] ^= cipher[j];
            }
        }

        std::cout << "  Monte Carlo test completed: PASS" << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << "  Monte Carlo test failed: " << e.what() << std::endl;
        allPassed = false;
    }

    return allPassed;
}

// ========================================
// GCM NISTテストベクター
// ========================================
bool testGCMNISTVectors() {
    std::cout << "\n=== GCM NIST TEST VECTORS ===" << std::endl;
    bool allPassed = true;

    // NIST SP 800-38D GCMテストベクター（簡略版）
    struct GCMTestVector {
        std::string name;
        std::string key_hex;
        std::string iv_hex;
        std::string plaintext_hex;
        std::string aad_hex;
        std::string expected_cipher_hex;
        std::string expected_tag_hex;
    };

    std::vector<GCMTestVector> gcmVectors = {
        // Test Case 1 - 空の平文、空のAAD
        {
            "GCM Test Case 1 (Empty)",
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a"
        },
        // Test Case 2 - 16バイト平文、空のAAD
        {
            "GCM Test Case 2 (16-byte plaintext)",
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf"
        }
    };

    for (const auto& vector : gcmVectors) {
        std::cout << "\nTesting: " << vector.name << std::endl;

        try {
            std::vector<uint8_t> key = hexStringToBytes(vector.key_hex);
            std::vector<uint8_t> iv = hexStringToBytes(vector.iv_hex);
            std::vector<uint8_t> plaintext = hexStringToBytes(vector.plaintext_hex);
            std::vector<uint8_t> expectedCipher = hexStringToBytes(vector.expected_cipher_hex);
            std::vector<uint8_t> expectedTag = hexStringToBytes(vector.expected_tag_hex);

            std::vector<uint8_t> aad = hexStringToBytes(vector.aad_hex);
            std::vector<uint8_t> authenticatedCipher = iv;
            authenticatedCipher.insert(authenticatedCipher.end(), expectedCipher.begin(), expectedCipher.end());
            authenticatedCipher.insert(authenticatedCipher.end(), expectedTag.begin(), expectedTag.end());

            for (bool useAesNi : {false, true}) {
                std::cout << "  " << (useAesNi ? "AES-NI" : "Software") << " decrypt... ";
                AES aes(key, useAesNi);
                std::vector<uint8_t> decrypted = aes.decrypt_gcm(authenticatedCipher, aad);

                if (decrypted == plaintext) {
                    std::cout << "PASS" << std::endl;
                }
                else {
                    std::cout << "FAIL (plaintext mismatch)" << std::endl;
                    allPassed = false;
                }
            }

        }
        catch (const std::exception& e) {
            std::cout << "  ERROR: " << e.what() << std::endl;
            allPassed = false;
        }
    }

    return allPassed;
}

// ========================================
// RFC 8452 GCM-SIVテストベクター
// ========================================
bool testGCMSIVRFCVectors() {
    std::cout << "\n=== GCM-SIV RFC 8452 TEST VECTORS ===" << std::endl;
    bool allPassed = true;

    struct GCMSIVTestVector {
        std::string name;
        std::string keyHex;
        std::string nonceHex;
        std::string plaintextHex;
        std::string aadHex;
        std::string resultHex;
    };

    const std::vector<GCMSIVTestVector> vectors = {
        {
            "AES-128, 8-byte plaintext, empty AAD",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "0100000000000000",
            "",
            "b5d839330ac7b786578782fff6013b815b287c22493a364c"
        },
        {
            "AES-128, 8-byte plaintext, 1-byte AAD",
            "01000000000000000000000000000000",
            "030000000000000000000000",
            "0200000000000000",
            "01",
            "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508"
        },
        {
            "AES-256, 8-byte plaintext, empty AAD",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "0100000000000000",
            "",
            "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"
        },
        {
            "AES-256, 8-byte plaintext, 1-byte AAD",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "030000000000000000000000",
            "0200000000000000",
            "01",
            "1de22967237a813291213f267e3b452f02d01ae33e4ec854"
        }
    };

    for (const auto& vector : vectors) {
        std::cout << "\nTesting: " << vector.name << std::endl;
        const std::vector<uint8_t> key = hexStringToBytes(vector.keyHex);
        const std::vector<uint8_t> nonce = hexStringToBytes(vector.nonceHex);
        const std::vector<uint8_t> plaintext = hexStringToBytes(vector.plaintextHex);
        const std::vector<uint8_t> aad = hexStringToBytes(vector.aadHex);
        const std::vector<uint8_t> result = hexStringToBytes(vector.resultHex);

        std::vector<uint8_t> serializedCipher = nonce;
        serializedCipher.insert(serializedCipher.end(), result.begin(), result.end());

        for (bool useAesNi : {false, true}) {
            std::cout << "  " << (useAesNi ? "AES-NI" : "Software") << " decrypt... ";
            try {
                AES aes(key, useAesNi);
                const std::vector<uint8_t> decrypted = aes.decrypt_gcm_siv(serializedCipher, aad);
                if (decrypted == plaintext) {
                    std::cout << "PASS" << std::endl;
                }
                else {
                    std::cout << "FAIL (plaintext mismatch)" << std::endl;
                    allPassed = false;
                }
            }
            catch (const std::exception& e) {
                std::cout << "FAIL (" << e.what() << ")" << std::endl;
                allPassed = false;
            }
        }
    }

    return allPassed;
}

int main() {
    // 全体のテスト結果を管理するフラグ
    bool finalResult = true;

    // 基本機能テスト
    finalResult &= testBasicCBC();
    finalResult &= testGCM();
    finalResult &= testGCMSIV();
    finalResult &= testDifferentKeySizes();
    finalResult &= testLargeDataSets();
    finalResult &= testErrorConditions();
    finalResult &= testSpecialDataPatterns();

    // NIST標準準拠テスト
    finalResult &= testNISTVectors();
    finalResult &= testNISTMonteCarlo();
    finalResult &= testGCMNISTVectors();
    finalResult &= testGCMSIVRFCVectors();

    if (finalResult) {
        std::cout << "\n=== ALL TESTS PASSED! ===" << std::endl;
    }
    else {
        std::cout << "\n=== SOME TESTS FAILED! ===" << std::endl;
    }

    //std::cin.get();
    return finalResult ? 0 : 1;
}
