#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstdint>

// p.10~4. Mathemaical Preliminaries(4.1, 4.2)
class GFPolynomial {
public:
    GFPolynomial(uint16_t c);

    std::string pprint() const;

    uint8_t getCoeffs() const;

    GFPolynomial operator+(const GFPolynomial& rhs) const;
    GFPolynomial operator*(const GFPolynomial& rhs) const;

private:
    static const uint16_t mod = 0x11b; // modulo x^8 + x^4 + x^3 + x + 1
    uint8_t coeffs;

    uint16_t bitLength(uint16_t n) const;
};

// 乗法的逆元の計算
void initInverse();

GFPolynomial inverse(const GFPolynomial& poly);
