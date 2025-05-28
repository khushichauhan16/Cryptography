#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

using namespace std;

class SHA1 {
private:
    static constexpr uint32_t H0 = 0x67452301;
    static constexpr uint32_t H1 = 0xEFCDAB89;
    static constexpr uint32_t H2 = 0x98BADCFE;
    static constexpr uint32_t H3 = 0x10325476;
    static constexpr uint32_t H4 = 0xC3D2E1F0;

    vector<uint32_t> hashValues{H0, H1, H2, H3, H4};

    static uint32_t leftRotate(uint32_t value, uint32_t bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    static vector<uint32_t> preprocessMessage(const string &message) {
        vector<uint8_t> data(message.begin(), message.end());
        uint64_t originalSize = data.size() * 8;
        data.push_back(0x80);
        while ((data.size() + 8) % 64 != 0) {
            data.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<uint8_t>(originalSize >> (i * 8)));
        }
        vector<uint32_t> result;
        for (size_t i = 0; i < data.size(); i += 4) {
            result.push_back((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]);
        }
        return result;
    }

    void processBlock(const vector<uint32_t> &block) {
        vector<uint32_t> W(80);
        for (int t = 0; t < 16; ++t) {
            W[t] = block[t];
        }
        for (int t = 16; t < 80; ++t) {
            W[t] = leftRotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        }
        uint32_t a = hashValues[0], b = hashValues[1], c = hashValues[2], d = hashValues[3], e = hashValues[4];
        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = leftRotate(a, 5) + f + e + k + W[t];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }
        hashValues[0] += a;
        hashValues[1] += b;
        hashValues[2] += c;
        hashValues[3] += d;
        hashValues[4] += e;
    }

public:
    string hash(const string &message) {
        vector<uint32_t> processedMessage = preprocessMessage(message);
        for (size_t i = 0; i < processedMessage.size(); i += 16) {
            vector<uint32_t> block(processedMessage.begin() + i, processedMessage.begin() + i + 16);
            processBlock(block);
        }
        stringstream result;
        for (uint32_t h : hashValues) {
            result << hex << setw(8) << setfill('0') << h;
        }
        return result.str();
    }
};

int main() {
    SHA1 sha1;
    string message;
    cout << "Enter the message: ";
    getline(cin, message);
    string hashValue = sha1.hash(message);
    cout << "SHA-1 Hash: " << hashValue << endl;
    return 0;
}
