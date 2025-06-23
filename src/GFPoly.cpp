#include "GFPoly.h"
#include <cassert>

GFPolynomial::GFPolynomial(uint16_t c) {
    if (c >= 0x100) {
        uint16_t temp_m = mod << (bitLength(c) - bitLength(mod));
        uint16_t tar = bitLength(c);

        while (c >= 0x100) {
            if ((c >> (tar - 1)) & 1) {
                c ^= temp_m;
            }
            temp_m >>= 1;
            tar--;
        }
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
    uint16_t res = 0;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; j++) {
            if (((coeffs >> i) & 1) && ((rhs.coeffs >> j) & 1)) {
                res ^= (1 << (i + j));
            }
        }
    }
    return GFPolynomial(res);
}

uint16_t GFPolynomial::bitLength(uint16_t n) const {
    uint32_t length = 0;
    while (n > 0) {
        length++;
        n >>= 1;
    }
    return length;
}

// 荵玲ｳ慕噪騾�蜈�縺ｮ險育ｮ�
std::vector<GFPolynomial> inverseTable(256, GFPolynomial(0));

void initInverse() {
    for (int i = 0; i < 256; ++i) {
        for (int j = 0; j < 256; ++j) {
            GFPolynomial res = GFPolynomial(i) * GFPolynomial(j);
            if (res.getCoeffs() == 1) {
                inverseTable[i] = GFPolynomial(j);
                break;
            }
        }
    }
}

GFPolynomial inverse(const GFPolynomial& poly) {
    return inverseTable[poly.getCoeffs()];
}