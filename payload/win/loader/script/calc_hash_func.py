from typing import Mapping

FUNCS = [
    # NTAPI
    "EtwEventWrite",
    "LdrLoadDll",
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtCreateFile",
    "NtCreateNamedPipeFile",
    "NtCreateProcessEx",
    "NtCreateSection",
    "NtCreateThreadEx",
    "NtDuplicateObject",
    "NtFlushInstructionCache",
    "NtFreeVirtualMemory",
    "NtGetContextThread",
    "NtMapViewOfSection",
    "NtOpenProcess",
    "NtOpenProcessToken",
    "NtOpenThread",
    "NtProtectVirtualMemory",
    "NtQueryInformationFile",
    "NtQueryInformationProcess",
    "NtQueryVirtualMemory",
    "NtReadFile",
    "NtReadVirtualMemory",
    "NtResumeThread",
    "NtSetContextThread",
    "NtSetInformationFile",
    "NtSetInformationProcess",
    "NtTerminateProcess",
    "NtUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtWaitForSingleObject",
    "NtWriteFile",
    "RtlAllocateHeap",
    "RtlCreateProcessReflection",
    "RtlCreateUserThread",
    "RtlExpandEnvironmentStrings",
    "RtlGetFullPathName_U",
    "RtlInitUnicodeString",
    "RtlQuerySystemInformation",
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
    "ConvertThreadToFiber",
    "CreateEventW",
    "CreateFiber",
    "CreatePipe",
    "CreateProcessW",
    "CreateRemoteThreadEx",
    "CreateThreadpoolWait",
    "CreateToolhelp32Snapshot",
    "CryptBinaryToStringW",
    "CryptStringToBinaryW",
    "EnumProcessModules",
    "ExpandEnvironmentStringsW",
    "FindWindowW",
    "FreeLibrary",
    "GetModuleBaseNameA",
    "GetModuleHandleA",
    "GetProcAddress",
    "GetSystemDirectoryW",
    "GetSystemInfo",
    "GetThreadContext",
    "GetWindowThreadProcessId",
    "ImageNtHeader",
    "IsDebuggerPresent",
    "LoadLibraryA",
    "LoadLibraryW",
    "LookupPrivilegeValueW",
    "MessageBoxA",
    "MessageBoxW",
    "OpenProcess",
    "OpenProcessToken",
    "OpenThread",
    "Process32FirstW",
    "Process32NextW",
    "QueueUserAPC",
    "ReadFile",
    "ReadProcessMemory",
    "ResumeThread",
    "SetHandleInformation",
    "SetThreadContext",
    "SetThreadpoolWait",
    "SuspendThread",
    "SwitchToFiber",
    "TerminateProcess",
    "Thread32First",
    "Thread32Next",
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualFree",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualQueryEx",
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
    "WSAStartup"
]

HASH_IV = 0x35
RANDOM_ADDR = 0xab10f29f

def calc_hash(string: str) -> int:
    str_length = len(string)
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
            print("The calculated hash is duplicate. Please try another algorithm.")
            return
        hashes[f"#define HASH_FUNC_{func.upper()}"] = hash_fmt

    max_length = max(len(api_name) for api_name in hashes.keys())

    for api_name, api_hash in hashes.items():
        print(f"{api_name.ljust(max_length)} {api_hash}")


if __name__ == "__main__":
    print("Set the following defines to a header file such as 'procs.hpp'.\n")
    main()
