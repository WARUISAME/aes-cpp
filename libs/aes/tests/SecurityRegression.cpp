#include "AES.h"
#include "detail/Validation.h"
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>

namespace {
void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
template <typename F>
void rejects(F operation) {
    try { operation(); }
    catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("Malformed input was not rejected as invalid_argument");
}
template <typename F>
void authenticationFails(F operation) {
    try { operation(); }
    catch (const std::runtime_error&) { return; }
    throw std::runtime_error("Unauthenticated input returned plaintext");
}
struct Capture {
    std::ostringstream output, error;
    std::streambuf* out = std::cout.rdbuf(output.rdbuf());
    std::streambuf* err = std::cerr.rdbuf(error.rdbuf());
    ~Capture() { std::cout.rdbuf(out); std::cerr.rdbuf(err); }
};

void checkCbc(AES& aes) {
    // Include IV-only input and %4-valid partial blocks that used to overflow SIMD buffers.
    for (size_t length = 0; length <= 81; ++length) {
        if (length >= 32 && (length - 16) % 16 == 0) continue;
        rejects([&] { aes.decrypt_cbc(std::vector<uint8_t>(length, 0)); });
    }
    for (size_t length : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(17), size_t(32), size_t(64)}) {
        const std::vector<uint8_t> plain(length, 0x41);
        auto encrypted = aes.encrypt_cbc(plain);
        require(encrypted.size() >= 32, "Empty plaintext must produce IV plus PKCS#7 block");
        require(aes.decrypt_cbc(encrypted) == plain, "CBC roundtrip changed");
    }
    // Use raw encryption with zero IV so decrypted padding is precisely controlled.
    for (unsigned int pad = 1; pad <= 16; ++pad) {
        std::vector<uint8_t> block(16, 0x41);
        std::fill(block.end() - pad, block.end(), static_cast<uint8_t>(pad));
        auto payload = aes.cipher(block);
        std::vector<uint8_t> serialized(16, 0);
        serialized.insert(serialized.end(), payload.begin(), payload.end());
        require(aes.decrypt_cbc(serialized) == std::vector<uint8_t>(16 - pad, 0x41), "Valid PKCS#7 padding rejected");
        if (pad > 1) {
            serialized[16 - pad] ^= 1; // IV changes one suffix byte but leaves last byte intact.
            rejects([&] { aes.decrypt_cbc(serialized); });
        }
    }
    for (uint8_t badPad : {uint8_t(0), uint8_t(17), uint8_t(255)}) {
        std::vector<uint8_t> block(16, badPad);
        auto payload = aes.cipher(block);
        std::vector<uint8_t> serialized(16, 0);
        serialized.insert(serialized.end(), payload.begin(), payload.end());
        rejects([&] { aes.decrypt_cbc(serialized); });
    }
}

void checkAead(AES& aes, bool supportsSiv) {
    const std::vector<uint8_t> plain(19, 0x41), aad = {1, 2, 3};
    for (size_t length = 0; length < 28; ++length) {
        rejects([&] { aes.decrypt_gcm(std::vector<uint8_t>(length, 0), aad); });
        if (supportsSiv) rejects([&] { aes.decrypt_gcm_siv(std::vector<uint8_t>(length, 0), aad); });
    }
    for (bool siv : {false, true}) {
        if (siv && !supportsSiv) continue;
        auto encrypted = siv ? aes.encrypt_gcm_siv(plain, aad) : aes.encrypt_gcm(plain, aad);
        auto decrypt = [&](const std::vector<uint8_t>& ct, const std::vector<uint8_t>& ad) {
            return siv ? aes.decrypt_gcm_siv(ct, ad) : aes.decrypt_gcm(ct, ad);
        };
        require(decrypt(encrypted, aad) == plain, "AEAD roundtrip changed");
        authenticationFails([&] { decrypt(encrypted, {9, 2, 3}); });
        for (size_t position : {size_t(0), size_t(12), encrypted.size() - 1}) {
            auto tampered = encrypted;
            tampered[position] ^= 1;
            authenticationFails([&] { decrypt(tampered, aad); });
        }
    }
}

void checkLengthLimits() {
    for (bool siv : {false, true}) {
        const uint64_t maxData = siv ? (1ULL << 36) : (1ULL << 36) - 32;
        const uint64_t maxAad = siv ? (1ULL << 36) : std::numeric_limits<uint64_t>::max() / 8;
        rejects([&] { aes_detail::validateAeadLengths(maxData + 1, 0, siv); });
        rejects([&] { aes_detail::validateAeadLengths(0, maxAad + 1, siv); });
        rejects([&] { aes_detail::validateAeadLengths(std::numeric_limits<uint64_t>::max(), 0, siv); });
        aes_detail::validateAeadLengths(0, 0, siv);
        aes_detail::validateAeadLengths(17, 3, siv);
        if (sizeof(size_t) >= 8) {
            aes_detail::validateAeadLengths(maxData, 0, siv);
            aes_detail::validateAeadLengths(0, maxAad, siv);
        } else {
            rejects([&] { aes_detail::validateAeadLengths(maxData, 0, siv); });
            rejects([&] { aes_detail::validateAeadLengths(0, maxAad, siv); });
            rejects([&] { aes_detail::validateAeadLengths(0xFFFFFFF0ULL, 0, siv); });
        }
    }
}
}

int main() {
    try {
        std::string capturedOut, capturedErr;
        {
            Capture capture;
            checkLengthLimits();
            for (size_t keySize : {size_t(16), size_t(24), size_t(32)}) {
                const std::vector<uint8_t> key(keySize, 0);
                AES software(key, false), hardware(key, true);
                checkCbc(software); checkCbc(hardware);
                checkAead(software, keySize != 24); checkAead(hardware, keySize != 24);
                for (int iteration = 0; iteration < 4; ++iteration) {
                    std::unique_ptr<AES> heap(new AES(key, true));
                    AES copy(*heap);
                    const std::vector<uint8_t> block(16, 0);
                    require(copy.cipher(block) == software.cipher(block), "Heap/copy SIMD key storage changed output");
                    require(copy.invCipher(software.cipher(block)) == block, "Heap/copy SIMD decryption failed");
                    auto encrypted = copy.encrypt_cbc({});
                    require(software.decrypt_cbc(encrypted).empty(), "Empty CBC backend compatibility failed");
                }
            }
            capturedOut = capture.output.str(); capturedErr = capture.error.str();
        }
        require(capturedOut.empty() && capturedErr.empty(), "Library emits keys or plaintext to standard streams");
        std::cout << "Security regression tests passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Security regression failure: " << e.what() << '\n';
        return 1;
    }
}
