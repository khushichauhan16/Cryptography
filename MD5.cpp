#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstdint>

using namespace std;

// Left rotate function
uint32_t left_rotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

// Constants for MD5
const uint32_t INIT_A = 0x67452301;
const uint32_t INIT_B = 0xefcdab89;
const uint32_t INIT_C = 0x98badcfe;
const uint32_t INIT_D = 0x10325476;

// Per-round shift amounts
const uint32_t s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// MD5 Constants (K[i] = floor(2^32 * abs(sin(i + 1))))
const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// Function to pad the input string
vector<uint8_t> preprocess(const string& message) {
    vector<uint8_t> msg(message.begin(), message.end());
    size_t original_len = msg.size();
    
    // Append the bit '1' (0x80 in hex)
    msg.push_back(0x80);

    // Padding with 0s until message length is 448 mod 512
    while (msg.size() % 64 != 56) {
        msg.push_back(0x00);
    }

    // Append the original length (in bits) as a 64-bit little-endian integer
    uint64_t bit_len = original_len * 8;
    for (int i = 0; i < 8; i++) {
        msg.push_back(static_cast<uint8_t>(bit_len & 0xFF));
        bit_len >>= 8;
    }

    return msg;
}

// Function to process each 512-bit block
void process_block(const vector<uint8_t>& block, uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D) {
    uint32_t M[16];
    for (int i = 0; i < 16; i++) {
        M[i] = (block[i * 4]) | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
    }

    uint32_t a = A, b = B, c = C, d = D;

    for (int i = 0; i < 64; i++) {
        uint32_t F, g;
        if (i < 16) {
            F = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            F = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            F = c ^ (b | ~d);
            g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + left_rotate(a + F + K[i] + M[g], s[i]);
        a = temp;
    }

    A += a;
    B += b;
    C += c;
    D += d;
}

// MD5 computation function
string md5(const string& input) {
    vector<uint8_t> msg = preprocess(input);
    uint32_t A = INIT_A, B = INIT_B, C = INIT_C, D = INIT_D;

    for (size_t i = 0; i < msg.size(); i += 64) {
        vector<uint8_t> block(msg.begin() + i, msg.begin() + i + 64);
        process_block(block, A, B, C, D);
    }

    stringstream result;
    uint32_t hash[] = { A, B, C, D };
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            result << hex << setw(2) << setfill('0') << (hash[i] & 0xFF);
            hash[i] >>= 8;
        }
    }

    return result.str();
}

int main() {
    string input;
    cout << "Enter the text to hash: ";
    getline(cin, input);

    string md5_hash = md5(input);
    cout << "MD5 Hash: " << md5_hash << endl;

    return 0;
}
