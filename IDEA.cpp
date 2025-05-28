#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstdint>

using namespace std;

const int ROUNDS = 8;

// Multiplication in GF(2^16 + 1)
uint16_t mul(uint16_t a, uint16_t b) {
    if (a == 0) a = 0x10000;
    if (b == 0) b = 0x10000;
    uint32_t result = (uint32_t)a * b;
    if (result >= 0x10001) result = (result % 0x10001) & 0xFFFF;
    return (result == 0x10000) ? 0 : result;
}

// Addition modulo 2^16
uint16_t add(uint16_t a, uint16_t b) {
    return (a + b) & 0xFFFF;
}

// Additive inverse
uint16_t addInv(uint16_t x) {
    return (0x10000 - x) & 0xFFFF;
}

// Multiplicative inverse in GF(2^16 + 1)
uint16_t mulInv(uint16_t x) {
    if (x <= 1) return x;
    uint16_t y = 0x10001, t0 = 1, t1 = 0;
    while (true) {
        t1 += y / x * t0;
        y %= x;
        if (y == 1) return (0x10001 - t1) & 0xFFFF;
        t0 += x / y * t1;
        x %= y;
        if (x == 1) return t0;
    }
}

// Expands a 16-byte key to subkeys
vector<uint16_t> expandKey(const vector<uint8_t>& key) {
    if (key.size() != 16) throw invalid_argument("Key must be 16 bytes long");
    vector<uint16_t> subKeys(ROUNDS * 6 + 4);
    for (int i = 0; i < 8; i++) {
        subKeys[i] = (key[2 * i] << 8) | key[2 * i + 1];
    }
    for (int i = 8; i < subKeys.size(); i++) {
        subKeys[i] = ((subKeys[(i + 1) % 8 ? i - 7 : i - 15] << 9) | (subKeys[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7)) & 0xFFFF;
    }
    return subKeys;
}

// Inverts encryption keys for decryption
vector<uint16_t> invertKey(const vector<uint16_t>& key) {
    vector<uint16_t> invKey(key.size());
    int p = 0, i = ROUNDS * 6;
    invKey[i] = mulInv(key[p++]);
    invKey[i + 1] = addInv(key[p++]);
    invKey[i + 2] = addInv(key[p++]);
    invKey[i + 3] = mulInv(key[p++]);
    for (int r = ROUNDS - 1; r >= 0; r--) {
        i = r * 6;
        int m = r > 0 ? 2 : 1;
        int n = r > 0 ? 1 : 2;
        invKey[i + 4] = key[p++];
        invKey[i + 5] = key[p++];
        invKey[i] = mulInv(key[p++]);
        invKey[i + m] = addInv(key[p++]);
        invKey[i + n] = addInv(key[p++]);
        invKey[i + 3] = mulInv(key[p++]);
    }
    return invKey;
}

// Encrypt/Decrypt 8-byte block
void crypt(vector<uint8_t>& data, const vector<uint16_t>& subKey) {
    uint16_t x0 = (data[0] << 8) | data[1];
    uint16_t x1 = (data[2] << 8) | data[3];
    uint16_t x2 = (data[4] << 8) | data[5];
    uint16_t x3 = (data[6] << 8) | data[7];
    
    int p = 0;
    for (int round = 0; round < ROUNDS; round++) {
        uint16_t y0 = mul(x0, subKey[p++]);
        uint16_t y1 = add(x1, subKey[p++]);
        uint16_t y2 = add(x2, subKey[p++]);
        uint16_t y3 = mul(x3, subKey[p++]);
        uint16_t t0 = mul(y0 ^ y2, subKey[p++]);
        uint16_t t1 = add(y1 ^ y3, t0);
        uint16_t t2 = mul(t1, subKey[p++]);
        uint16_t t3 = add(t0, t2);
        x0 = y0 ^ t2;
        x1 = y2 ^ t2;
        x2 = y1 ^ t3;
        x3 = y3 ^ t3;
    }
    uint16_t r0 = mul(x0, subKey[p++]);
    uint16_t r1 = add(x2, subKey[p++]);
    uint16_t r2 = add(x1, subKey[p++]);
    uint16_t r3 = mul(x3, subKey[p++]);
    
    data[0] = r0 >> 8; data[1] = r0;
    data[2] = r1 >> 8; data[3] = r1;
    data[4] = r2 >> 8; data[5] = r2;
    data[6] = r3 >> 8; data[7] = r3;
}

int main() {
    vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    vector<uint16_t> encSubKey = expandKey(key);
    vector<uint16_t> decSubKey = invertKey(encSubKey);
    vector<uint8_t> data = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    
    cout << "Original Data: ";
    for (auto d : data) cout << hex << (int)d << " ";
    cout << endl;
    
    crypt(data, encSubKey);
    cout << "Encrypted Data: ";
    for (auto d : data) cout << hex << (int)d << " ";
    cout << endl;
    
    crypt(data, decSubKey);
    cout << "Decrypted Data: ";
    for (auto d : data) cout << hex << (int)d << " ";
    cout << endl;
    
    return 0;
}
