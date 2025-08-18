#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>

#include "aes.h"

#pragma comment(lib, "advapi32.lib")

// Hàm chuyển đổi hex string thành bytes
std::vector<BYTE> hexStringToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Struct cho AES key blob
struct AESKeyBlob {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE rgbKeyData[16]; // 128-bit key
};

std::vector<BYTE> AESDecryptor::aes_decrypt(const std::vector<BYTE>& encrypted,
    const std::string& keyHex,
    const std::string& ivHex) {

    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    std::vector<BYTE> decrypted;

    try {
        // Chuyển đổi hex strings thành bytes
        std::vector<BYTE> keyBytes = hexStringToBytes(keyHex);
        std::vector<BYTE> ivBytes = hexStringToBytes(ivHex);

        // Kiểm tra kích thước
        if (keyBytes.size() != 16 || ivBytes.size() != 16) {
            //throw std::runtime_error("Key & IV length must be 16 bytes (128-bit)");
            throw std::runtime_error("");
        }

        // Acquire crypto context
        if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            //throw std::runtime_error("Cannot acquire crypto context");
            throw std::runtime_error("");
        }

        // Tạo AES key blob
        AESKeyBlob keyBlob;
        keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
        keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        keyBlob.hdr.reserved = 0;
        keyBlob.hdr.aiKeyAlg = CALG_AES_128;
        keyBlob.dwKeySize = 16; // 128-bit
        memcpy(keyBlob.rgbKeyData, keyBytes.data(), 16);

        // Import key
        if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(AESKeyBlob), 0, 0, &hKey)) {
            //throw std::runtime_error("Cannot import AES key");
            throw std::runtime_error("");
        }

        // Set CBC mode
        DWORD dwMode = CRYPT_MODE_CBC;
        if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0)) {
            //throw std::runtime_error("Cannot set CBC mode");
            throw std::runtime_error("");
        }

        // Set IV
        if (!CryptSetKeyParam(hKey, KP_IV, ivBytes.data(), 0)) {
            //throw std::runtime_error("Cannot set IV");
            throw std::runtime_error("");
        }

        // Set padding mode to None (equivalent to PaddingMode.None in C#)
        DWORD dwPadding = 3; // PKCS5_PADDING = 1, None = 3
        if (!CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)&dwPadding, 0)) {
            // Nếu không set được None padding, thử không set gì (default behavior)
        }

        // Logic giống như C# code gốc:
        // Code C# tạo CryptoStream với CryptoStreamMode.Write và ghi toàn bộ ciphertext vào
        // Điều này có nghĩa là nó decrypt toàn bộ data mà không quan tâm đến padding rules

        // Tính toán kích thước cần thiết (làm tròn lên đến bội số của 16)
        size_t originalSize = encrypted.size();
        size_t paddedSize = ((originalSize + 15) / 16) * 16;

        // Tạo buffer với padding
        decrypted.resize(paddedSize);

        // Copy data và pad với zeros nếu cần
        std::copy(encrypted.begin(), encrypted.end(), decrypted.begin());
        if (paddedSize > originalSize) {
            std::fill(decrypted.begin() + originalSize, decrypted.end(), 0);
        }

        DWORD dataLen = static_cast<DWORD>(paddedSize);

        // Decrypt toàn bộ data
        if (!CryptDecrypt(hKey, 0, FALSE, 0, decrypted.data(), &dataLen)) {
            // Thử với final = FALSE nếu TRUE failed
            dataLen = static_cast<DWORD>(paddedSize);
            if (!CryptDecrypt(hKey, 0, FALSE, 0, decrypted.data(), &dataLen)) {
                // Thử decrypt từng block riêng lẻ
                decrypted.resize(paddedSize);
                std::copy(encrypted.begin(), encrypted.end(), decrypted.begin());
                if (paddedSize > originalSize) {
                    std::fill(decrypted.begin() + originalSize, decrypted.end(), 0);
                }

                const size_t blockSize = 16;
                for (size_t i = 0; i < paddedSize; i += blockSize) {
                    DWORD blockLen = blockSize;
                    BOOL isLastBlock = (i + blockSize >= paddedSize);
                    if (!CryptDecrypt(hKey, 0, isLastBlock, 0, decrypted.data() + i, &blockLen)) {
                        //throw std::runtime_error("Decryption failed at block");
                        throw std::runtime_error("");
                    }
                }
                dataLen = static_cast<DWORD>(paddedSize);
            }
        }

        // Giữ nguyên kích thước ban đầu (giống như C# code)
        decrypted.resize(originalSize);

    }
    catch (const std::exception& e) {
        // Cleanup
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw; // Re-throw exception
    }

    // Cleanup
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);

    return decrypted;
}

// Hàm helper để chuyển string thành bytes (tương đương Encoding.UTF8.GetBytes)
std::vector<BYTE> aes_decrypt_string_keys(const std::vector<BYTE>& encrypted,
    const std::string& keyString,
    const std::string& ivString) {

    // Chuyển string thành hex (giả sử key và IV là UTF-8 strings)
    std::ostringstream keyHex, ivHex;
    for (char c : keyString) {
        keyHex << std::hex << std::setw(2) << std::setfill('0') << (unsigned char)c;
    }
    for (char c : ivString) {
        ivHex << std::hex << std::setw(2) << std::setfill('0') << (unsigned char)c;
    }

    return AESDecryptor::aes_decrypt(encrypted, keyHex.str(), ivHex.str());
}

// Test function
void testDecryption() {
    try {
        // Example usage
        std::string keyString = "1234567890123456"; // 16 chars = 128 bits
        std::string ivString = "abcdefghijklmnop";  // 16 chars = 128 bits

        // Sample encrypted data (you would provide your actual encrypted data)
        std::vector<BYTE> encrypted = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

        std::vector<BYTE> decrypted = aes_decrypt_string_keys(encrypted, keyString, ivString);

        //std::cout << "Decryption successfully! Size: " << decrypted.size() << " bytes" << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << "Lỗi: " << e.what() << std::endl;
    }
}