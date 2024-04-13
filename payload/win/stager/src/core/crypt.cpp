#include "core/crypt.hpp"

namespace Crypt
{
    VOID GenerateKeyAndIV()
    {
        // TODO
        // ...
    }

    std::vector<BYTE> XOR(const std::vector<BYTE>& input, const std::vector<BYTE>& key)
    {
        std::vector<BYTE> output;

        for (size_t i = 0; i < input.size(); ++i) {
            output.push_back(input[i] ^ key[i % key.size()]);
        }

        return output;
    }

    std::wstring Base64Encode(const std::vector<BYTE>& data)
    {
        // Get correct size.
        DWORD dw64Len = 0;
        if (!CryptBinaryToStringW(
            data.data(),
            static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            NULL,
            &dw64Len
        )) {
            return L"";
        }

        // Encode
        std::vector<wchar_t> w64(dw64Len);
        if (!CryptBinaryToStringW(
            data.data(),
            static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            w64.data(),
            &dw64Len
        )) {
            return L"";
        }

        // If the last character is null-terminated string, remove it.
        if (!w64.empty() && w64.back() == L'\0')
        {
            w64.pop_back();
        }

        return std::wstring(w64.begin(), w64.end());
    }

    std::vector<BYTE> Base64Decode(const std::wstring& w64)
    {
        // Get correct size.
        DWORD cbBinary = 0;
        if (!CryptStringToBinaryW(
            w64.c_str(),
            w64.length(),
            CRYPT_STRING_BASE64,
            NULL,
            &cbBinary,
            NULL,
            NULL
        )) {
            return std::vector<BYTE>();
        }

        // Decode.
        std::vector<BYTE> bytes(cbBinary);
        if (!CryptStringToBinaryW(
            w64.c_str(),
            w64.length(),
            CRYPT_STRING_BASE64,
            bytes.data(),
            &cbBinary,
            NULL,
            NULL
        )) {
            return std::vector<BYTE>();
        }

        return bytes;
    }

    std::wstring Encrypt(const std::vector<BYTE>& plaindata)
    {
        // TODO: Implement encryption
        // ...

        // HEX encode
        std::wstring w64 = Base64Encode(plaindata);
        // std::string s64 = Utils::Convert::UTF8Encode(w64);

        // // XOR
        // std::string sKey = "secret";
        // std::vector<BYTE> xorBytes = XOR(
        //     std::vector<BYTE>(s64.begin(), s64.end()), std::vector<BYTE>(sKey.begin(), sKey.end())
        // );

        // // HEX encode
        // std::wstring cipherdata = Base64Encode(xorBytes);

        return w64;
    }

    std::vector<BYTE> Decrypt(const std::wstring& cipherdata)
    {
        // HEX decode
        std::vector<BYTE> cipherdataDec = Base64Decode(cipherdata);

        // XOR
        // std::string sKey = "secret";
        // std::vector<BYTE> xorBytes = XOR(cipherdataDec, std::vector<BYTE>(sKey.begin(), sKey.end()));

        // // HEX decode
        // std::vector<BYTE> plaindata = Base64Decode(
        //     Utils::Convert::UTF8Decode(std::string(xorBytes.begin(), xorBytes.end()))
        // );

        // TODO: Implement decryption
        // ...

        return cipherdataDec;
    }
}