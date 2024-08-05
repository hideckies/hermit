from typing import Mapping

FUNCS = [
    # NTAPI
    "EtwEventWrite",
    "LdrLoadDll",
    "NtAdjustPrivilegesToken",
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtCreateFile",
    "NtCreateNamedPipeFile",
    "NtCreateProcessEx",
    "NtCreateThreadEx",
    "NtDeleteFile",
    "NtDuplicateObject",
    "NtEnumerateValueKey",
    "NtFlushInstructionCache",
    "NtFreeVirtualMemory",
    "NtGetContextThread",
    "NtOpenFile",
    "NtOpenKeyEx",
    "NtOpenProcess",
    "NtOpenProcessToken",
    "NtOpenThread",
    "NtPrivilegeCheck",
    "NtProtectVirtualMemory",
    "NtQueryInformationFile",
    "NtQueryInformationProcess",
    "NtQueryInformationToken",
    "NtQueryKey",
    "NtQuerySystemInformation",
    "NtReadFile",
    "NtReadVirtualMemory",
    "NtResumeThread",
    "NtSetContextThread",
    "NtSetInformationFile",
    "NtSetInformationProcess",
    "NtSystemDebugControl",
    "NtTerminateProcess",
    "NtTraceEvent",
    "NtUnmapViewOfSection",
    "NtWaitForSingleObject",
    "NtWriteFile",
    "NtWriteVirtualMemory",
    "RtlAllocateHeap",
    "RtlExpandEnvironmentStrings",
    "RtlGetCurrentDirectory_U",
    "RtlGetFullPathName_U",
    "RtlInitUnicodeString",
    "RtlQuerySystemInformation",
    "RtlSetCurrentDirectory_U",
    "RtlStringCchCatW",
    "RtlStringCchCopyW",
    "RtlStringCchLengthW",
    "RtlZeroMemory",

    # WINAPI
    "AdjustTokenPrivileges",
    "AmsiScanBuffer",
    "BCryptCloseAlgorithmProvider",
    "BCryptDecrypt",
    "BCryptDestroyKey",
    "BCryptEncrypt",
    "BCryptGenerateSymmetricKey",
    "BCryptGetProperty",
    "BCryptOpenAlgorithmProvider",
    "BCryptSetProperty",
    "CheckRemoteDebuggerPresent",
    "CloseHandle",
    "CoCreateInstance",
    "CoInitializeEx",
    "CoInitializeSecurity",
    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
    "CoUninitialize",
    "CreateFileW",
    "CreatePipe",
    "CreateProcessW",
    "CreateProcessWithLogonW",
    "CreateProcessWithTokenW",
    "CreateRemoteThreadEx",
    "CreateThreadpoolWait",
    "CreateWindowExW",
    "CryptBinaryToStringW",
    "CryptStringToBinaryW",
    "DeleteFileW",
    "DispatchMessage",
    "DllMain",
    "DuplicateTokenEx",
    "ExpandEnvironmentStringsW",
    "FindClose",
    "FindFirstFileW",
    "FindNextFileW",
    "FormatMessageW",
    "FreeEnvironmentStringsW",
    "FreeLibrary",
    "GetAdaptersAddresses",
    "GetComputerNameW",
    "GetComputerNameExW",
    "GetEnvironmentStringsW",
    "GetExitCodeProcess",
    "GetForegroundWindow",
    "GetLastError",
    "GetLocalTime",
    "GetMessage",
    "GetModuleFileNameW",
    "GetModuleHandleA",
    "GetProcAddress",
    "GetProcessHeap",
    "GetProcessImageFileNameW",
    "GetSystemDirectoryW",
    "GetSystemInfo",
    "GetSystemMetrics",
    "GetSystemTime",
    "GetTcpTable",
    "GetTickCount",
    "GetTokenInformation",
    "GetUserNameW",
    "GetVersionExW",
    "GlobalAlloc",
    "GlobalFree",
    "HeapAlloc",
    "HeapFree",
    "ImpersonateLoggedOnUser",
    "IsDebuggerPresent",
    "LoadAcceleratorsW",
    "LoadCursorW",
    "LoadIconW",
    "LoadLibraryA",
    "LoadLibraryW",
    "LocalAlloc",
    "LocalFree",
    "LookupAccountNameW",
    "LookupPrivilegeNameW",
    "LookupPrivilegeValueW",
    "MessageBoxA",
    "MessageBoxW",
    "MiniDumpWriteDump",
    "MoveFileW",
    "NetApiBufferFree",
    "NetLocalGroupEnum",
    "NetUserAdd",
    "NetUserDel",
    "NetUserEnum",
    "OpenProcess",
    "OpenProcessToken",
    "PrivilegeCheck",
    "QueryFullProcessImageNameW",
    "ReadFile",
    "ReadProcessMemory",
    "RegCloseKey",
    "RegCreateKeyExW",
    "RegDeleteKeyExW",
    "RegDeleteValueW",
    "RegEnumKeyExW",
    "RegEnumValueW",
    "RegisterClassExW",
    "RegOpenKeyExW",
    "RegQueryInfoKeyW",
    "RegSaveKeyW",
    "RegSetValueExW",
    "RemoveDirectoryW",
    "RevertToSelf",
    "RpcStringFreeW",
    "RtlAddFunctionTable",
    "RtlCopyMemory",
    "SetFileInformationByHandle",
    "SetHandleInformation",
    "SetThreadContext",
    "SetThreadpoolWait",
    "ShellExecuteExW",
    "ShowWindow",
    "SystemTimeToFileTime",
    "TerminateProcess",
    "TranslateAcceleratorW",
    "TranslateMessage",
    "UpdateWindow",
    "UuidCreate",
    "UuidToStringW",
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualFree",
    "WinHttpCloseHandle",
    "WinHttpConnect",
    "WinHttpOpen",
    "WinHttpOpenRequest",
    "WinHttpQueryDataAvailable",
    "WinHttpQueryHeaders",
    "WinHttpReadData",
    "WinHttpReceiveResponse",
    "WinHttpSendRequest",
    "WinHttpSetOption",
    "WinHttpWriteData",
    "WriteProcessMemory",
    "WSACleanup",
    "WSAStartup",
]

HASH_IV = 0x35
RANDOM_ADDR = 0xab10f29f

def calc_hash(string: str) -> int:
    hash = HASH_IV

    for s in string:
        # hash = ((hash << 5) + hash) + ord(s)
        hash = hash * RANDOM_ADDR + ord(s)

    return hash & 0xFFFFFFFF


def is_dupl(hashes: Mapping[str, str], hash: str) -> bool:
    for v in hashes.values():
        if v == hash:
            return True
    return False


def main():
    hashes = {}

    for func in FUNCS:
        hash_value = calc_hash(func)
        hash_fmt = f"{'0x{0:x}'.format(hash_value)}"
        # Check if the hash is duplicate
        if is_dupl(hashes, hash_fmt) is True:
            print("The calculated hash is duplicate. Please update algorithm.")
            return
        hashes[f"#define HASH_FUNC_{func.upper()}"] = hash_fmt

    max_length = max(len(api_name) for api_name in hashes.keys())

    for api_name, api_hash in hashes.items():
        print(f"{api_name.ljust(max_length)} {api_hash}")


if __name__ == "__main__":
    print("Set the following defines to a header file such as 'procs.hpp'.\n")
    main()
