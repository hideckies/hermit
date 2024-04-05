#include "core/crypt.hpp"

namespace Crypt
{
    VOID GenerateKeyAndIV()
    {
        // TODO
        // ...
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

    std::string HexEncodeData(const std::vector<char>& data)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (char c : data)
        {
            ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(c));
        }
        return ss.str();
    }

    std::vector<char> HexDecodeData(const std::string& sHex)
    {
        std::vector<char> result;
        for (size_t i = 0; i < sHex.length(); i += 2)
        {
            char byte = static_cast<char>(std::stoi(sHex.substr(i, 2), nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }

    std::string EncryptData(const std::vector<char>& plaindata)
    {
        std::string encodedData = HexEncodeData(plaindata);

        // TODO: Implement encryption
        // ...

        return encodedData;
    }

    std::vector<char> DecryptData(const std::string& cipherdata)
    {
        std::vector<char> decodedData = HexDecodeData(cipherdata);

        // TODO: Implement decryption
        // ...

        return decodedData;
    }
}