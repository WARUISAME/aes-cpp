#pragma once
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace aes_detail {
inline void validateAeadLengths(uint64_t dataBytes, uint64_t aadBytes, bool siv) {
    const uint64_t maxData = siv ? (1ULL << 36) : ((1ULL << 36) - 32);
    const uint64_t maxAad = siv ? (1ULL << 36) : (std::numeric_limits<uint64_t>::max() / 8ULL);
    if (dataBytes > maxData || aadBytes > maxAad) {
        throw std::invalid_argument("AEAD input exceeds the mode's size limit");
    }
    const uint64_t maxSize = std::numeric_limits<size_t>::max();
    const uint64_t paddedData = dataBytes + (16 - dataBytes % 16) % 16;
    const uint64_t paddedAad = aadBytes + (16 - aadBytes % 16) % 16;
    if (paddedData + paddedAad + 16 > maxSize || dataBytes + 28 > maxSize) {
        throw std::invalid_argument("AEAD input exceeds this platform's buffer size");
    }
}
}
