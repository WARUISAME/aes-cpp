#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <cassert>

class GFPolynomial {
public:
    GFPolynomial(uint16_t c);

    std::string pprint() const;

    uint8_t getCoeffs() const;

    GFPolynomial operator+(const GFPolynomial& rhs) const;
    GFPolynomial operator*(const GFPolynomial& rhs) const;

private:
    static const uint16_t mod = 0x11b;
    uint8_t coeffs;

    uint16_t bitLength(uint16_t n) const;
};

void initInverse();

GFPolynomial inverse(const GFPolynomial& poly);
