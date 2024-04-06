#include "core/crypt.hpp"

namespace Crypt
{
    VOID GenerateKeyAndIV()
    {
        // TODO
        // ...
    }

    BYTE hexCharToByte(char cHex)
    {
        if ('0' <= cHex && cHex <= '9')
        {
            return cHex - '0';
        }
        else if ('a' <= cHex && cHex <= 'f')
        {
            return cHex - 'a' + 10;
        }
        else if ('A' <= cHex && cHex <= 'F')
        {
            return cHex - 'A' + 10;
        }

        return 0;
    }

    std::wstring HexEncode(const std::wstring& wStr)
    {
        std::string sStr = Utils::Convert::UTF8Encode(wStr);

        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0');
        for (unsigned char c : sStr)
        {
            oss << std::setw(2) << static_cast<int>(c);
        }
        return Utils::Convert::UTF8Decode(oss.str());
    }

    std::wstring HexDecode(const std::wstring& wHex)
    {
        std::vector<unsigned char> bytes;

        for (size_t i = 0; i < wHex.length(); i += 2)
        {
            unsigned int byteValue;
            std::wstringstream(wHex.substr(i, 2)) >> std::hex >> byteValue;
            bytes.push_back(static_cast<unsigned char>(byteValue));
        }
        
        std::string sDecoded(bytes.begin(), bytes.end());
        std::wstring wDecoded = Utils::Convert::UTF8Decode(sDecoded);
        return wDecoded;
    }

    std::wstring Encrypt(const std::wstring& wPlaintext)
    {
        // TODO: Implement encryption
        // ...

        std::wstring wEncoded = HexEncode(wPlaintext);
        return wEncoded;
    }

    std::wstring Decrypt(const std::wstring& wCiphertext)
    {
        std::wstring wDecoded = HexDecode(wCiphertext);

        // TODO: Implement decryption
        // ...

        return wDecoded;
    }

    std::string HexEncodeData(const std::vector<BYTE>& data)
    {
        std::stringstream ss;
        for (BYTE byte : data)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<INT>(byte);
        }
        return ss.str();
    }

    std::vector<BYTE> HexDecodeData(const std::string& sHex)
    {
        std::vector<BYTE> result;
        for (size_t i = 0; i < sHex.length(); i += 2)
        {
            BYTE high = hexCharToByte(sHex[i]);
            BYTE low = hexCharToByte(sHex[i + 1]);
            result.push_back((high << 4) | low);
        }
        return result;
    }

    std::string EncryptData(const std::vector<BYTE>& plaindata)
    {
        std::string encodedData = HexEncodeData(plaindata);

        // TODO: Implement encryption
        // ...

        return encodedData;
    }

    std::vector<BYTE> DecryptData(const std::string& cipherdata)
    {
        std::vector<BYTE> decodedData = HexDecodeData(cipherdata);

        // TODO: Implement decryption
        // ...

        return decodedData;
    }
}