#ifndef HERMIT_CORE_CRYPT_HPP
#define HERMIT_CORE_CRYPT_HPP

#include <windows.h>
#include <wincrypt.h>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>

#include "core/stdout.hpp"
#include "core/utils.hpp"

#define AES_KEY_LENGTH 16
#define AES_IV_LENGTH 16

namespace Crypt
{
    struct AES
    {
        BYTE key[AES_KEY_LENGTH];
        BYTE iv[AES_IV_LENGTH];
    };

    struct CRYPT
    {
        AES aes;
    };

    typedef CRYPT* PCRYPT;

    VOID GenerateKeyAndIV();

    std::vector<BYTE> XOR(const std::vector<BYTE>& input, const std::vector<BYTE>& key);
    std::wstring Base64Encode(const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(const std::wstring& w64);
    std::wstring Encrypt(const std::vector<BYTE>& plaindata);
    std::vector<BYTE> Decrypt(const std::wstring& cipherdata);
}

#endif // HERMIT_CORE_CRYPT_HPP