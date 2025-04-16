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
    AES aes(key,true);

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

    AES aes2(key, false);

    auto cipher2 = aes2.encrypt_cbc(plaintext_bytes);

    auto decrypted2 = aes2.decrypt_cbc(cipher2);
    std::string recovered2(
        reinterpret_cast<const char*>(decrypted2.data()),
        decrypted2.size());

    std::cout << "Original: " << plaintext << "\n";
    std::cout << "Recovered: " << recovered2 << "\n";

    std::cin.get();

    return 0;
}
