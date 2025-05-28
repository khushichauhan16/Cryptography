#include <cstdint>
#include <iostream>
#include <vector>
#include <iomanip> // For hex formatting

// Constants for RC5-32/12/16
const int W = 32; // Word size in bits
const int R = 12; // Number of rounds
const int B = 16; // Key size in bytes
const int C = 4;  // Number of words in key

// Magic constants
const uint32_t P = 0xB7E15163;
const uint32_t Q = 0x9E3779B9;

// Rotate left function
uint32_t rotl(uint32_t x, int y)
{
    return (x << y) | (x >> (W - y));
}

// Rotate right function
uint32_t rotr(uint32_t x, int y)
{
    return (x >> y) | (x << (W - y));
}

// RC5 key expansion
void rc5_key_setup(const std::vector<uint8_t>& key, std::vector<uint32_t>& S)
{
    std::vector<uint32_t> L(C, 0);
    for (int i = B - 1; i >= 0; --i) {
        L[i / 4] = (L[i / 4] << 8) + key[i];
    }

    std::cout << "Key Schedule L: ";
    for (uint32_t word : L)
        std::cout << std::hex << word << " ";
    std::cout << std::endl;

    S[0] = P;
    for (int i = 1; i < 2 * (R + 1); ++i) {
        S[i] = S[i - 1] + Q;
    }

    std::cout << "Initial S Array: ";
    for (uint32_t word : S)
        std::cout << std::hex << word << " ";
    std::cout << std::endl;

    uint32_t A = 0, B = 0;
    int i = 0, j = 0;
    for (int k = 0; k < 3 * std::max(2 * (R + 1), C); ++k) {
        A = S[i] = rotl(S[i] + A + B, 3);
        B = L[j] = rotl(L[j] + A + B, (A + B) % W);
        i = (i + 1) % (2 * (R + 1));
        j = (j + 1) % C;
    }

    std::cout << "Final S Array: ";
    for (uint32_t word : S)
        std::cout << std::hex << word << " ";
    std::cout << std::endl;
}

// RC5 encryption
void rc5_encrypt(const std::vector<uint32_t>& S, uint32_t& A, uint32_t& B)
{
    A += S[0];
    B += S[1];

    for (int i = 1; i <= R; ++i) {
        A = rotl(A ^ B, B % W) + S[2 * i];
        B = rotl(B ^ A, A % W) + S[2 * i + 1];
    }
}

int main()
{
    std::vector<uint8_t> key = { 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00 };  //8 bit*16=128 bits
    std::vector<uint32_t> S(2 * (R + 1), 0);

    rc5_key_setup(key, S);

    uint32_t A = 0x00000023;
    uint32_t B = 0x00000000;

    std::cout << "\nPlaintext: " << std::hex << A << " " << B << std::endl;

    rc5_encrypt(S, A, B);

    std::cout << "Ciphertext: " << std::hex << A << " " << B << std::endl;

    return 0;
}
