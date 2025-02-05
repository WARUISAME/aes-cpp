#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <memory>

int main() {
    // 鍵の大きさによって強度が変わる。
    // 128bit鍵は16byte
    // 192bit鍵は24byte
    // 256bit鍵は32byte

    // 鍵と平文を定義
    std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> iv = {0xf4, 0x87, 0xe6, 0xd6, 0xde, 0xaa, 0xc8, 0xff, 0x95, 0x50, 0x87, 0xb8, 0x87, 0x53, 0xf9, 0xba};
    std::vector<uint8_t> plain_text = {'I', ' ', 'a', 'm', ' ', 'k', 'u', 'r', 'e', 'n', 'a', 'i', 'f', '!', '!', '!'};

    std::vector<uint8_t> key256 = {0x72, 0x69, 0xd4, 0xf3, 0xa7, 0xff, 0xb3, 0x5a, 0xb7, 0x4a, 0x6b, 0xf9, 0xf1, 0xc3, 0x68, 0x6e, 0x1b, 0x12, 0xf8, 0x75, 0xcf, 0x50, 0xa9, 0xdd, 0x0f, 0xed, 0xda, 0x46, 0xcf, 0xdc, 0x4e, 0x37};

    std::unique_ptr<AES> aes = std::make_unique<AES>();

    // AES暗号化
    std::vector<uint8_t> cipher_text = aes->encrypt(plain_text, key);

    // AES復号化
    std::vector<uint8_t> decrypted_text = aes->decrypt(cipher_text, key);

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

    plain_text = { 't', 'h', 'e', ' ', 'm', 'a', 'g', 'i', 'c', ' ', 'w', 'o', 'r', 'd', 's', ' ', 'a', 'r', 'e', ' ', 's', 'q', 'u', 'e', 'a', 'm', 'i', 's', 'h', ' ', 'o', 's', 's', 'i', 'f', 'r', 'a', 'g', 'e', ' ', 'T', 'o', ' ', 'k', 'n', 'o', 'w', ' ', 'i', 's', ' ', 't', 'o', ' ', 'k', 'n', 'o', 'w', ' ', 't', 'h', 'a', 't', ' ', 'y', 'o', 'u', ' ', 'k', 'n', 'o', 'w', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', ' ', 'T', 'h', 'a', 't', ' ', 'i', 's', ' ', 't', 'h', 'e', ' ', 't', 'r', 'u', 'e', ' ', 'm', 'e', 'a', 'n', 'i', 'n', 'g', ' ', 'o', 'f', ' ', 'k', 'n', 'o', 'w', 'l', 'e', 'd', 'g', 'e' };
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
    

    std::vector<uint8_t> ciphertextZ = aes->encryptAESNI_cbc(plain_text, key256);
    std::vector<uint8_t> decryptedZ = aes->decryptAESNI_cbc(ciphertextZ, key256);
    for (size_t i = 0; i < decryptedZ.size(); i++) {
        printf("%02x ", decryptedZ[i]);
    }
    printf("\n");

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

    std::cin.get();

    return 0;
}
