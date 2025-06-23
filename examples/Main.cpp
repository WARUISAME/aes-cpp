#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <memory>

int main() {
    /*// 鍵の作成用 
    std::vector<uint8_t> IV(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    */


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

    std::cin.get();

    return 0;
}
