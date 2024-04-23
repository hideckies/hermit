#include "core/crypt.hpp"

namespace Crypt
{
    std::wstring Base64Encode(const std::vector<BYTE>& data)
    {
        // Get correct size.
        DWORD dw64Len = 0;
        if (!CryptBinaryToStringW(
            data.data(),
            static_cast<DWORD>(data.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
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
            nullptr,
            &cbBinary,
            nullptr,
            nullptr
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
            nullptr,
            nullptr
        )) {
            return std::vector<BYTE>();
        }

        return bytes;
    }

    
    std::vector<BYTE> PadPKCS7(const std::vector<BYTE>& data, DWORD cbBlockLen)
    {
        size_t padSize = cbBlockLen - (data.size() % cbBlockLen);
        std::vector<BYTE> paddedData = data;
        for (size_t i = 0; i < padSize; ++i) {
            // paddedData.push_back(static_cast<BYTE>(padSize));
            paddedData.insert(paddedData.begin(), static_cast<BYTE>(padSize));
        }
        return paddedData;
    }

    std::vector<BYTE> UnpadPKCS7(const std::vector<BYTE>& data, DWORD dwPadLen)
    {
        // size_t padding = static_cast<size_t>(data[dwPadLen - 1]);
        // std::vector<BYTE> unpaddedData(data.begin() + padding, data.end());
        return std::vector<BYTE>(data.begin() + dwPadLen, data.end());
    }

    PCRYPT InitCrypt(const std::wstring& wKey64, const std::wstring& wIV64)
    {
        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_KEY_HANDLE hKey;
        PBYTE pbKey = nullptr;
        PBYTE pbIV = nullptr;
        PBYTE pbKeyObj = nullptr;
        DWORD cbKeyObj = 0;
        DWORD cbBlockLen = 0;
        DWORD cbData = 0;

        // Decode Base64 key/iv
        std::vector<BYTE> key = Base64Decode(wKey64);
        std::vector<BYTE> iv = Base64Decode(wIV64);

        // Open algorithm provider.
        if (BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0
        ) != 0) {
            return nullptr;
        }

        // Calculate the size of the buffer to hold the key object.
        if (BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE)&cbKeyObj,
            sizeof(DWORD),
            &cbData,
            0
        ) != 0) {
            return nullptr;
        }

        // Allocate the key object on the heap.
        pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
        if (pbKeyObj == nullptr)
        {
            return nullptr;
        }

        // Calculate the block length.
        if (BCryptGetProperty(
            hAlg,
            BCRYPT_BLOCK_LENGTH,
            (PBYTE)&cbBlockLen,
            sizeof(DWORD),
            &cbData,
            0
        ) != 0) {
            return nullptr;
        }

        if (cbBlockLen > iv.size())
        {
            return nullptr;
        }

        if (BCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0
        ) != 0) {
            return nullptr;
        }

        // Generate key object.
        if (BCryptGenerateSymmetricKey(
            hAlg,
            &hKey,
            pbKeyObj,
            cbKeyObj,
            (PBYTE)key.data(),
            (ULONG)key.size(),
            0
        ) != 0) {
            return nullptr;
        }

        // Set the state
        PAES pAES = new AES;
        pAES->hAlg = hAlg;
        pAES->hKey = hKey;
        pAES->key = key;
        pAES->iv = iv;
        pAES->pbKeyObj = pbKeyObj;
        pAES->cbKeyObj = cbKeyObj;
        pAES->cbBlockLen = cbBlockLen;

        PCRYPT pCrypt = new CRYPT;
        pCrypt->pAES = pAES;

        return pCrypt;
    }

    std::wstring Encrypt(
        const std::vector<BYTE> plaindata,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    ) {
        DWORD cbData = 0;
        
        // Get the output buffer size.
        if(BCryptEncrypt(
            hKey,
            (PBYTE)plaindata.data(),
            plaindata.size(),
            nullptr,
            iv.data(),
            iv.size(),
            nullptr,
            0,
            &cbData,
            BCRYPT_BLOCK_PADDING
        ) != 0) {
            return L"";
        }

        std::vector<BYTE> cipherdata(cbData);

        // Use the key to encrypt the plaintext buffer.
        // For block sized messages, block padding will add an extra block.
        if(BCryptEncrypt(
            hKey,
            (PBYTE)plaindata.data(),
            plaindata.size(),
            nullptr,
            iv.data(),
            iv.size(),
            cipherdata.data(),
            cipherdata.size(),
            &cbData,
            BCRYPT_BLOCK_PADDING
        ) != 0) {
            return L"";
        }

        // Base64 encode
        return Base64Encode(cipherdata);
    }

    std::vector<BYTE> Decrypt(
        const std::wstring& ciphertext,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    ) {
        DWORD cbPlaindata = 0;
        NTSTATUS ntStatus;

        // Decode Base64
        std::vector<BYTE> cipherdata = Base64Decode(ciphertext);
        
        // Get the output buffer size.
        ntStatus = BCryptDecrypt(
            hKey, 
            cipherdata.data(),
            cipherdata.size(),
            nullptr,
            iv.data(),
            iv.size(),
            nullptr, 
            0, 
            &cbPlaindata, 
            BCRYPT_BLOCK_PADDING
        );
        if (ntStatus != STATUS_SUCCESS)
        {
            return std::vector<BYTE>();
        }

        std::vector<BYTE> plaindata(cbPlaindata);
  
        ntStatus = BCryptDecrypt(
            hKey, 
            cipherdata.data(),
            cipherdata.size(),
            nullptr,
            iv.data(),
            iv.size(),
            plaindata.data(),
            plaindata.size(),
            &cbPlaindata, 
            BCRYPT_BLOCK_PADDING
        );
        if (ntStatus != STATUS_SUCCESS)
        {
            return std::vector<BYTE>();
        }
        
        // Unpadding
        std::vector<BYTE> plaindataUnpad = UnpadPKCS7(plaindata, iv.size());

        return plaindataUnpad;
    }

    VOID Cleanup(
        BCRYPT_ALG_HANDLE hAlg,
        BCRYPT_KEY_HANDLE hKey,
        PBYTE pbKeyObj
    ) {
        if(hAlg)
        {
            BCryptCloseAlgorithmProvider(hAlg,0);
        }

        if (hKey)    
        {
            BCryptDestroyKey(hKey);
        }

        if(pbKeyObj)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObj);
        }
    }
}
