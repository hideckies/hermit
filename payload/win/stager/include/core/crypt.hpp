#ifndef HERMIT_CORE_CRYPT_HPP
#define HERMIT_CORE_CRYPT_HPP

#include <windows.h>
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
    BYTE hexCharToByte(char cHex);
    
    // For Strings
    std::wstring HexEncode(const std::wstring& wStr);
    std::wstring HexDecode(const std::wstring& wHex);
    std::wstring Encrypt(const std::wstring& wPlaintext);
    std::wstring Decrypt(const std::wstring& wCiphertext);
    // For Binary Data
    std::string HexEncodeData(const std::vector<BYTE>& data);
    std::vector<BYTE> HexDecodeData(const std::string& sHex);
    std::string EncryptData(const std::vector<BYTE>& plaindata);
    std::vector<BYTE> DecryptData(const std::string& cipherdata);
}

#endif // HERMIT_CORE_CRYPT_HPP