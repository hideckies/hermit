#ifndef HERMIT_CORE_CRYPT_HPP
#define HERMIT_CORE_CRYPT_HPP

#include "core/procs.hpp"
#include "core/stdout.hpp"
#include "core/utils.hpp"

#include <windows.h>
#include <iomanip>
#include <ntstatus.h>
#include <string>
#include <sstream>
#include <vector>

#define AES_KEY_LENGTH 16
#define AES_IV_LENGTH 16

namespace Crypt
{
    struct AES
    {
        BCRYPT_ALG_HANDLE   hAlg;
        BCRYPT_KEY_HANDLE   hKey;
        std::vector<BYTE>   key;
        std::vector<BYTE>   iv;
        PBYTE               pbKeyObj;
        DWORD               cbKeyObj; 
        DWORD               cbBlockLen;
    };
    typedef AES* PAES;

    struct CRYPT
    {
        PAES pAES;
    };
    typedef CRYPT* PCRYPT;

    std::wstring Base64Encode(Procs::PPROCS pProcs, const std::vector<BYTE>& data);
    std::vector<BYTE> Base64Decode(Procs::PPROCS pProcs, const std::wstring& w64);

    std::vector<BYTE> PadPKCS7(const std::vector<BYTE>& data, DWORD cbBlockLen);
    std::vector<BYTE> UnpadPKCS7(const std::vector<BYTE>& data, DWORD dwPadLen);

    PCRYPT InitCrypt(
        Procs::PPROCS pProcs,
        const std::wstring& wKey64,
        const std::wstring& wIV64
    );
    std::wstring Encrypt(
        Procs::PPROCS pProcs,
        const std::vector<BYTE> plaindata,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    );
    std::vector<BYTE> Decrypt(
        Procs::PPROCS pProcs,
        const std::wstring& ciphertext,
        BCRYPT_KEY_HANDLE hKey,
        std::vector<BYTE> iv
    );
    VOID Cleanup(
        Procs::PPROCS pProcs,
        BCRYPT_ALG_HANDLE hAlg,
        BCRYPT_KEY_HANDLE hKey,
        PBYTE pbKeyObj
    );
}

#endif // HERMIT_CORE_CRYPT_HPP