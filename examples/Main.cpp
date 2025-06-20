#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <memory>

//void test_roundtrip(const std::string& test_name, const std::vector<uint8_t>& data) {
//    std::vector<uint8_t> key(16, 0x55); // AES-128キー
//    AES aes(key);
//
//    try {
//        auto cipher = aes.encryptAESNI_cbc(data, key);
//        auto decrypted = aes.decryptAESNI_cbc(cipher, key);
//
//        if (decrypted != data) {
//            std::cerr << "TEST FAILED: " << test_name
//                << "\nOriginal size: " << data.size()
//                << "\nDecrypted size: " << decrypted.size()
//                << "\nContent mismatch!\n";
//        }
//    }
//    catch (const std::exception& e) {
//        std::cerr << "TEST ERROR: " << test_name
//            << "\nException: " << e.what() << "\n";
//    }
//}
//
//void test_known_vector() {
//    // NISTテストベクタ（例）
//    std::vector<uint8_t> key = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
//                               0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
//    std::vector<uint8_t> plain = { 'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!' };
//
//    AES aes(key);
//
//    auto cipher = aes.encryptAESNI_cbc(plain, key);
//    auto decrypted = aes.decryptAESNI_cbc(cipher, key);
//
//    assert(plain == decrypted);
//}
//
//void test_key_expansion() {
//    std::vector<uint8_t> key = {
//        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
//    };
//
//    AES aes(key);
//
//    std::vector<uint32_t> w = aes.keyExpansion(key, 4, 4, 10);
//    assert(w[40] == 0xd014f9a8); // 最終ラウンドキーの検証
//}

int main() {
    // 鍵の大きさによって強度が変わる。
    // 128bit鍵は16byte
    // 192bit鍵は24byte
    // 256bit鍵は32byte

    // 鍵と平文を定義
    //std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    //std::vector<uint8_t> iv = {0xf4, 0x87, 0xe6, 0xd6, 0xde, 0xaa, 0xc8, 0xff, 0x95, 0x50, 0x87, 0xb8, 0x87, 0x53, 0xf9, 0xba};
    //std::vector<uint8_t> plain_text = {'I', ' ', 'a', 'm', ' ', 'k', 'u', 'r', 'e', 'n', 'a', 'i', 'f', '!', '!', '!'};

    //std::vector<uint8_t> key256 = {0x72, 0x69, 0xd4, 0xf3, 0xa7, 0xff, 0xb3, 0x5a, 0xb7, 0x4a, 0x6b, 0xf9, 0xf1, 0xc3, 0x68, 0x6e, 0x1b, 0x12, 0xf8, 0x75, 0xcf, 0x50, 0xa9, 0xdd, 0x0f, 0xed, 0xda, 0x46, 0xcf, 0xdc, 0x4e, 0x37};

    //std::unique_ptr<AES> aes = std::make_unique<AES>(key256);

    //// AES暗号化
    //std::vector<uint8_t> cipher_text = aes->encrypt(plain_text, key);

    //// AES復号化
    //std::vector<uint8_t> decrypted_text = aes->decrypt(cipher_text, key);

    // 平文と一致するか確認
    //assert(decrypted_text == plain_text);

    // 結果を出力
    /*std::cout << "plain text: ";
    for (auto c : plain_text) std::cout << c;
    std::cout << std::endl;

    std::cout << "cipher text: ";
    for (auto c : cipher_text) std::cout << std::hex << (int)c << " ";
    std::cout << std::endl;

    std::cout << "decrypt by C++ AES: ";
    for (auto c : decrypted_text) std::cout << c;
    std::cout << std::endl;


    plain_text = { 'I', ' ', 'a', 'm', ' ', 'k', 'u', 'r', 'e', 'n', 'a', 'i', 'f', '!', '!', '!', ' ', 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'l', 'o', 'n', 'g', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', '.' };
    cipher_text = aes->encrypt_cbc(plain_text, key);
    decrypted_text = aes->decrypt_cbc(cipher_text, key);

    std::cout << "cipher text: ";
    for (auto c : cipher_text) std::cout << std::hex << (int)c << " ";
    std::cout << std::endl;

    std::cout << "decrypt by C++ AES: ";
    for (auto c : decrypted_text) std::cout << c;
    std::cout << std::endl;

    

    std::cout << "key: ";
    for (auto c : key) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << ", ";
    std::cout << std::endl;*/

    /*plain_text = { 't', 'h', 'e', ' ', 'm', 'a', 'g', 'i', 'c', ' ', 'w', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' ', 's', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'o', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e', ' ', 'T', 'o', ' ', 'k', 'n', 'o', 'w', ' ', 'i', 's', ' ', 't', 'o', ' ', 'k', 'n', 'o', 'w', ' ', 't', 'h', 'a', 't', ' ', 'y', 'o', 'u', ' ', 'k', 'n', 'o', 'w', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', ' ', 'T', 'h', 'a', 't', ' ', 'i', 's', ' ', 't', 'h', 'e', ' ', 't', 'r', 'u', 'e', ' ', 'm', 'e', 'a', 'n', 'i', 'n', 'g', ' ', 'o', 'f', ' ', 'k', 'n', 'o', 'w', 'l', 'e', 'd', 'g', 'e' };
    cipher_text = aes->encrypt_cbc(plain_text, key256, iv);
    decrypted_text = aes->decrypt_cbc(cipher_text, key256, iv);

    std::cout << "plain text: ";
    for (auto c : plain_text) std::cout << c;
    std::cout << std::endl;

    std::cout << "cipher text: ";
    for (auto c : cipher_text) std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    std::cout << std::endl;

    std::cout << "decrypt by C++ AES: ";
    for (auto c : decrypted_text) std::cout << c;
    std::cout << std::endl;
    */

    //test_key_expansion();
    //test_known_vector();

    //// テストケース実行例
    //test_roundtrip("Empty vector", {});
    //test_roundtrip("15-byte data", { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 });
    //test_roundtrip("16-byte data", std::vector<uint8_t>(16, 0xff));
    //test_roundtrip("17-byte data", std::vector<uint8_t>(17, 0xaa));


    /*std::vector<uint8_t> ciphertextZ = aes->encryptAESNI_cbc(plain_text, key256);
    std::vector<uint8_t> decryptedZ = aes->decryptAESNI_cbc(ciphertextZ, key256);
    for (size_t i = 0; i < decryptedZ.size(); i++) {
        printf("%02x ", decryptedZ[i]);
    }
    printf("\n");*/

    /*// 鍵の作成用 
    std::vector<uint8_t> IV(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 16; ++i) {
        IV[i] = static_cast<uint8_t>(dis(gen));
    }

    std::cout << "IV: ";
    for (auto c : IV) std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)c << ", ";
    std::cout << std::endl;
    */

    
    std::vector<uint8_t> key = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    // AES-NIを使用して暗号・復号化
    //AES aes(key,true);

    // テストケース 1: 提供されたコードのキーと平文
    std::vector<uint8_t> key1(32, 0x77);
    std::string plaintext1 = "Testing with a 256-bit key.";
    std::cout << "TEST CASE 1:" << std::endl;
    std::cout << "PlainText: " << plaintext1 << std::endl;
    AES aes1(key1, false);
    AES aes1n(key1, true);
    std::vector<uint8_t> plaintext_bytes1(plaintext1.begin(), plaintext1.end());
    std::cout << "SOFT ENCRYPT" << std::endl;
    auto cipher1 = aes1.encrypt_cbc(plaintext_bytes1);
    std::cout << "AES-NI ENCRYPT" << std::endl;
    auto cipher1n = aes1n.encrypt_cbc(plaintext_bytes1);

    std::cout << "SOFT DECRYPT" << std::endl;
    auto decrypted1 = aes1.decrypt_cbc(cipher1);
    std::cout << "AES-NI DECRYPT" << std::endl;
    auto decrypted1n = aes1n.decrypt_cbc(cipher1n);

    std::cout << "AES-NI TO SOFT DECRYPT" << std::endl;
    auto decrypted1_n = aes1.decrypt_cbc(cipher1n);
    std::cout << "SOFT TO AES-NI DECRYPT" << std::endl;
    auto decrypted1n_1 = aes1n.decrypt_cbc(cipher1);

    std::string recovered1(
        reinterpret_cast<const char*>(decrypted1.data()),
        decrypted1.size());
    std::string recovered1n(
        reinterpret_cast<const char*>(decrypted1n.data()),
        decrypted1n.size());

    std::string recovered1_n(
        reinterpret_cast<const char*>(decrypted1_n.data()),
        decrypted1_n.size());
    std::string recovered1n_1(
        reinterpret_cast<const char*>(decrypted1n_1.data()),
        decrypted1n_1.size());

    std::cout << "SoftWare Decrypt: " << recovered1 << "\n";
    std::cout << "AES-NI Decrypt: " << recovered1n << "\n";

    std::cout << "SoftWare To AES-NI Decrypt: " << recovered1_n << std::endl;
    std::cout << "AES-NI To SoftWare Decrypt: " << recovered1n_1 << std::endl;
    for (auto c : cipher1) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";

    /*
    // 暗号化
    std::string plaintext = "Secret message";
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    auto cipher = aes.encrypt_cbc(plaintext_bytes);

    // 復号
    auto decrypted = aes.decrypt_cbc(cipher);
    std::string recovered(
        reinterpret_cast<const char*>(decrypted.data()),
        decrypted.size());

    std::cout << "Original: " << plaintext << "\n";
    std::cout << "Recovered: " << recovered << "\n";

    std::cout << "============================" << std::endl;

    AES aes2(key, true);

    auto cipher2 = aes2.encrypt_cbc(plaintext_bytes);

    std::vector<uint8_t> test = { 0xcc, 0xe9, 0x8f, 0xb3, 0xee, 0xeb, 0x8d, 0x45,
    0x54, 0x0d, 0x27, 0xc5, 0x3f, 0x63, 0xdc, 0x67,
    0x99, 0x52, 0xdd, 0x7c, 0xb2, 0x00, 0xe0, 0xff,
    0xe0, 0x72, 0x1c, 0x66, 0x39, 0x5e, 0x3a, 0x30,
    0x11, 0x99, 0x8c, 0xe8, 0xa9, 0x18, 0x0d, 0x71,
    0x7e, 0x64, 0xd8, 0xd8, 0x8d, 0xb2, 0x0c, 0xe8,
    0x74, 0x81, 0xdf, 0x2e, 0x38, 0x52, 0x46, 0xab,
    0xb6, 0x10, 0xb4, 0xed, 0xb2, 0x67, 0x7e, 0x97
    };

    auto decrypted2 = aes2.decrypt_cbc(cipher);
    std::string recovered2(
        reinterpret_cast<const char*>(decrypted2.data()),
        decrypted2.size());

    std::cout << "Original: " << plaintext << "\n";
    std::cout << "Recovered: " << recovered2 << "\n";
    */
    std::cin.get();

    return 0;
}
