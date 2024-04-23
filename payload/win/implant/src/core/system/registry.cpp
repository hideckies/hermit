#include "core/system.hpp"

namespace System::Registry
{
    HANDLE RegOpenKey(
        Procs::PPROCS       pProcs,
        const std::wstring& wKeyPath, // e.g. MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment
        DWORD               dwAccessMask // e.g. KEY_ALL_ACCESS
    ) {
        HANDLE hKey;
        UNICODE_STRING uniKeyPath;
        OBJECT_ATTRIBUTES oa;

        CallSysInvoke(
            &pProcs->sysRtlInitUnicodeString,
            pProcs->lpRtlInitUnicodeString,
            &uniKeyPath,
            wKeyPath.c_str()
        );
        InitializeObjectAttributes(&oa, &uniKeyPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        NTSTATUS status = CallSysInvoke(
            &pProcs->sysNtOpenKeyEx,
            pProcs->lpNtOpenKeyEx,
            &hKey,
            dwAccessMask,
            &oa,
            0
        );
        if (status != STATUS_SUCCESS)
        {
            Stdout::DisplayMessageBoxW(
                Utils::Convert::DWORDToWstring(status).c_str(),
                L"NtOpenKeyEx status"
            );
            return nullptr;
        }

        return hKey;
    }
}
