#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include "GFPoly.h"

// p.12~ 4.3 Polynomials with Coefficients in GF(2^8)
class GFCPolynomial {
public:
    // cs[0] + cs[1] x + cs[2] x^2 + cs[3] x^3
    GFCPolynomial(const std::vector<uint8_t>& coeffs) : cs(4,GFPolynomial(0)) {
        assert(coeffs.size() <= 4);
        for (size_t i = 0; i < coeffs.size(); ++i) {
            this->cs[i] = GFPolynomial(coeffs[i]);
        }
    }

    std::string pprint() const {
        std::string res = "";
        for (int i = 3; i >= 0; --i) {
            if (i != 3) {
                res += " + ";
            }
            res += "{" + cs[i].pprint() + "}*x^" + std::to_string(i);
        }
        return res;
    }

    std::vector<GFPolynomial> getCs() const {
        return cs;
    }

    GFCPolynomial operator+(const GFCPolynomial& rhs) const {
        GFCPolynomial res({});
        for (int i = 0; i < 4; ++i) { // GF(2^8) の足し算を行う
            res.cs[i] = this->cs[i] + rhs.cs[i];
        }
        return res;
    }

    GFCPolynomial operator*(const GFCPolynomial& rhs) const {
        GFCPolynomial res({});
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                res.cs[(i + j) % 4] = res.cs[(i + j) % 4] + (this->cs[i] * rhs.cs[j]);
            }
        }
        return res;
    }

private:
    std::vector<GFPolynomial> cs;
};