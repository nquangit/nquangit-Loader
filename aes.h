#pragma once
#include <string>
#include <vector>
#include <Windows.h> // Add this to ensure BYTE is defined

class AESDecryptor {
public:
    static std::vector<BYTE> aes_decrypt(const std::vector<BYTE>& encrypted,
        const std::string& keyHex,
        const std::string& ivHex);
};

std::vector<BYTE> aes_decrypt_string_keys(const std::vector<BYTE>& encrypted,
    const std::string& keyString,
    const std::string& ivString);