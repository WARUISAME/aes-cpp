#include "Sbox.h"

namespace {
uint8_t rotateByte(uint8_t value, unsigned int shift) {
    return static_cast<uint8_t>((static_cast<uint32_t>(value) << shift)
        | (static_cast<uint32_t>(value) >> (8 - shift)));
}
}

uint8_t Sbox(uint8_t b) {
    // FIPS 197 SubBytes: field inversion followed by the affine transform.
    const uint8_t a = inverse(GFPolynomial(b)).getCoeffs();
    return static_cast<uint8_t>(a ^ rotateByte(a, 1) ^ rotateByte(a, 2)
        ^ rotateByte(a, 3) ^ rotateByte(a, 4) ^ 0x63);
}

uint8_t invSbox(uint8_t b) {
    // Undo the affine transform before inversion. No secret-indexed tables.
    const uint8_t a = static_cast<uint8_t>(
        rotateByte(b, 1) ^ rotateByte(b, 3) ^ rotateByte(b, 6) ^ 0x05);
    return inverse(GFPolynomial(a)).getCoeffs();
}
