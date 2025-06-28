#include "AES.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <iomanip>
#include <memory>

int main() {
    // 鍵の作成用 
    std::vector<uint8_t> key1(32);
    std::random_device rd;

    for (size_t i = 0; i < 32; ++i) {
        key1[i] = static_cast<uint8_t>(rd() & 0xFF);
    }

    std::string plaintext1 = "the magic words are squeamish ossifrage To know is to know that you know nothing That is the true meaning of knowledge";
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
    
    // テスト結果の検証を追加
    bool all_tests_passed = true;

    if (recovered1 != plaintext1) {
        std::cout << "ERROR: Software decrypt failed!" << std::endl;
        all_tests_passed = false;
    }

    if (recovered1n != plaintext1) {
        std::cout << "ERROR: AES-NI decrypt failed!" << std::endl;
        all_tests_passed = false;
    }

    if (recovered1_n != plaintext1) {
        std::cout << "ERROR: Cross-compatibility (AES-NI->Software) failed!" << std::endl;
        all_tests_passed = false;
    }

    if (recovered1n_1 != plaintext1) {
        std::cout << "ERROR: Cross-compatibility (Software->AES-NI) failed!" << std::endl;
        all_tests_passed = false;
    }

    if (all_tests_passed) {
        std::cout << "\nAll tests PASSED!" << std::endl;
    }
    else {
        std::cout << "\nSome tests FAILED!" << std::endl;
    }

    std::cout << "\nCipher (hex)" << std::endl;
    for (size_t i = 0; i < cipher1.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)cipher1[i];
        if ((i + 1) % 16 == 0) {
            std::cout << '\n';
        }
        else {
            std::cout << ' ';
        }
    }

    std::cin.get();
    return 0;
}
