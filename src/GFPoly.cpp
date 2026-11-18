#include "GFPoly.h"
#include <cassert>

GFPolynomial::GFPolynomial(uint16_t c) {
    // Reduce every possible uint16_t input in eight fixed steps.
    // Masks and shifts depend only on public loop positions, never on coefficients.
    for (int bit = 15; bit >= 8; --bit) {
        const uint32_t mask = 0u - ((static_cast<uint32_t>(c) >> bit) & 1u);
        c ^= static_cast<uint16_t>((static_cast<uint32_t>(mod) << (bit - 8)) & mask);
    }
    coeffs = c;
    assert(coeffs < mod);
}

std::string GFPolynomial::pprint() const {
    std::string res = "";
    for (int i = 7; i >= 0; i--) {
        if ((coeffs >> i) & 1) {
            if (!res.empty()) {
                res += " + ";
            }
            res += "x^" + std::to_string(i);
        }
    }
    return res;
}

uint8_t GFPolynomial::getCoeffs() const {
    return coeffs;
}

GFPolynomial GFPolynomial::operator+(const GFPolynomial& rhs) const {
    return GFPolynomial(coeffs ^ rhs.coeffs);
}

GFPolynomial GFPolynomial::operator*(const GFPolynomial& rhs) const {
    uint32_t a = coeffs;
    uint32_t b = rhs.coeffs;
    uint32_t product = 0;
    // Carryless multiplication modulo x^8 + x^4 + x^3 + x + 1.
    // Always process all eight bits, including zero operands.
    for (int bit = 0; bit < 8; ++bit) {
        product ^= a & (0u - (b & 1u));
        a = ((a << 1) & 0xffu) ^ (0x1bu & (0u - (a >> 7)));
        b >>= 1;
    }
    return GFPolynomial(static_cast<uint16_t>(product));
}

// Kept for source compatibility. Inversion no longer needs shared table state.
void initInverse() {}

GFPolynomial inverse(const GFPolynomial& poly) {
    // Fixed addition chain for a^254 in GF(2^8). This also maps zero to zero,
    // as required by the AES S-box, without a secret-dependent special case.
    const GFPolynomial a2 = poly * poly;
    const GFPolynomial a3 = a2 * poly;
    const GFPolynomial a6 = a3 * a3;
    const GFPolynomial a12 = a6 * a6;
    const GFPolynomial a15 = a12 * a3;
    const GFPolynomial a30 = a15 * a15;
    const GFPolynomial a60 = a30 * a30;
    const GFPolynomial a120 = a60 * a60;
    const GFPolynomial a240 = a120 * a120;
    const GFPolynomial a252 = a240 * a12;
    return a252 * a2;
}
