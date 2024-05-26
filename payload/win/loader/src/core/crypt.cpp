#include "core/crypt.hpp"

namespace Crypt
{
    std::wstring Base64Encode(Procs::PPROCS pProcs, const std::vector<BYTE>& data)
    {
        // Get correct size.
        DWORD dw64Len = 0;
        if (!pProcs->lpCryptBinaryToStringW(
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
        if (!pProcs->lpCryptBinaryToStringW(
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

    std::vector<BYTE> Base64Decode(Procs::PPROCS pProcs, const std::wstring& w64)
    {
        // Get correct size.
        DWORD cbBinary = 0;
        if (!pProcs->lpCryptStringToBinaryW(
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
        if (!pProcs->lpCryptStringToBinaryW(
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

    PCRYPT InitCrypt(Procs::PPROCS pProcs, const std::wstring& wKey64, const std::wstring& wIV64)
    {
        BCRYPT_ALG_HANDLE hAlg;
        BCRYPT_KEY_HANDLE hKey;
        PBYTE pbKey = NULL;
        PBYTE pbIV = NULL;
        PBYTE pbKeyObj = NULL;
        DWORD cbKeyObj = 0;
        DWORD cbBlockLen = 0;
        DWORD cbData = 0;

        // Decode Base64 key/iv
        std::vector<BYTE> key = Base64Decode(pProcs, wKey64);
        std::vector<BYTE> iv = Base64Decode(pProcs, wIV64);

        // Open algorithm provider.
        if (pProcs->lpBCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0
        ) != 0) {
            return nullptr;
        }

        // Calculate the size of the buffer to hold the key object.
        if (pProcs->lpBCryptGetProperty(
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
        if (pbKeyObj == NULL)
        {
            return nullptr;
        }

        // Calculate the block length.
        if (pProcs->lpBCryptGetProperty(
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

        if (pProcs->lpBCryptSetProperty(
            hAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0
        ) != 0) {
            return nullptr;
        }

        // Generate key object.
        if (pProcs->lpBCryptGenerateSymmetricKey(
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
        Procs::PPROCS pProcs,
        const std::vector<BYTE> plaindata,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    ) {
        DWORD cbData = 0;
        
        // Get the output buffer size.
        if(pProcs->lpBCryptEncrypt(
            hKey,
            (PBYTE)plaindata.data(),
            plaindata.size(),
            NULL,
            iv.data(),
            iv.size(),
            NULL,
            0,
            &cbData,
            BCRYPT_BLOCK_PADDING
        ) != 0) {
            return L"";
        }

        std::vector<BYTE> cipherdata(cbData);

        // Use the key to encrypt the plaintext buffer.
        // For block sized messages, block padding will add an extra block.
        if(pProcs->lpBCryptEncrypt(
            hKey,
            (PBYTE)plaindata.data(),
            plaindata.size(),
            NULL,
            iv.data(),
            iv.size(),
            cipherdata.data(),
            cipherdata.size(),
            &cbData,
            BCRYPT_BLOCK_PADDING
        ) != 0) {
            return L"";
        }

        return Base64Encode(pProcs, cipherdata);
    }

    std::vector<BYTE> Decrypt(
        Procs::PPROCS pProcs,
        const std::wstring& ciphertext,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    ) {
        DWORD cbPlaindata = 0;
        NTSTATUS ntStatus;

        std::vector<BYTE> cipherdata = Base64Decode(pProcs, ciphertext);
        
        ntStatus = pProcs->lpBCryptDecrypt(
            hKey, 
            cipherdata.data(),
            cipherdata.size(),
            NULL,
            iv.data(),
            iv.size(),
            NULL, 
            0, 
            &cbPlaindata, 
            BCRYPT_BLOCK_PADDING
        );
        if (ntStatus != STATUS_SUCCESS)
        {
            return std::vector<BYTE>();
        }

        std::vector<BYTE> plaindata(cbPlaindata);
  
        ntStatus = pProcs->lpBCryptDecrypt(
            hKey, 
            cipherdata.data(),
            cipherdata.size(),
            NULL,
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
        Procs::PPROCS pProcs,
        BCRYPT_ALG_HANDLE hAlg,
        BCRYPT_KEY_HANDLE hKey,
        PBYTE pbKeyObj
    ) {
        if(hAlg)
        {
            pProcs->lpBCryptCloseAlgorithmProvider(hAlg,0);
        }

        if (hKey)    
        {
            pProcs->lpBCryptDestroyKey(hKey);
        }

        if(pbKeyObj)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObj);
        }
    }
}
