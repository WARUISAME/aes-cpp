#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <limits>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#elif defined(__linux__)
#include <sys/random.h>
#include <cerrno>
#else
#error "Secure random generation currently supports Windows and Linux."
#endif

namespace aes_detail {
inline void randomBytes(uint8_t* output, size_t size) {
    while (size) {
#ifdef _WIN32
        auto count = static_cast<ULONG>((size > (std::numeric_limits<ULONG>::max)())
            ? (std::numeric_limits<ULONG>::max)() : size);
        if (BCryptGenRandom(nullptr, output, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw std::runtime_error("BCryptGenRandom failed");
#else
        auto count = ::getrandom(output, size > 262144 ? 262144 : size, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("getrandom failed");
        }
        if (!count) throw std::runtime_error("getrandom returned no data");
#endif
        output += count;
        size -= static_cast<size_t>(count);
    }
}
}
