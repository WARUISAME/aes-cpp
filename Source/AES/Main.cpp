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
    std::vector<uint8_t> iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> plain_text = {'I', ' ', 'a', 'm', ' ', 'k', 'u', 'r', 'e', 'n', 'a', 'i', 'f', '!', '!', '!'};

    std::unique_ptr<AES> aes = std::make_unique<AES>();

    // AES暗号化
    std::vector<uint8_t> cipher_text = aes->encrypt(plain_text, key);

    // AES復号化
    std::vector<uint8_t> decrypted_text = aes->decrypt(cipher_text, key);

    // 平文と一致するか確認
    //assert(decrypted_text == plain_text);

    // 結果を出力
    std::cout << "plain text: ";
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

    std::vector<uint8_t> IV(32);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 32; ++i) {
        IV[i] = static_cast<uint8_t>(dis(gen));
    }

    std::cout << "key: ";
    for (auto c : key) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << ", ";
    std::cout << std::endl;

    std::cout << "IV: ";
    for (auto c : IV) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << ", ";
    std::cout << std::endl;
    

    return 0;
}
