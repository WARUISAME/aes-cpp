#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include "GFPoly.h"

int main() {
    // 鍵と平文を定義
    std::vector<uint8_t> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    std::vector<uint8_t> plain_text = {'I', ' ', 'a', 'm', ' ', 'k', 'u', 'r', 'e', 'n', 'a', 'i', 'f', '!', '!', '!'};

    // 逆元テーブルの初期化
    initInverse();

    // AES暗号化
    std::vector<uint8_t> cipher_text = encrypt(plain_text, key);

    // AES復号化
    std::vector<uint8_t> decrypted_text = decrypt(cipher_text, key);

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
    cipher_text = encrypt_cbc(plain_text, key);
    decrypted_text = decrypt_cbc(cipher_text, key);

    std::cout << "cipher text: ";
    for (auto c : cipher_text) std::cout << std::hex << (int)c << " ";
    std::cout << std::endl;

    std::cout << "decrypt by C++ AES: ";
    for (auto c : decrypted_text) std::cout << c;
    std::cout << std::endl;

    return 0;
}