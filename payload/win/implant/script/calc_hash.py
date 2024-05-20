from typing import Mapping

MODULES = [
    "KERNEL32.DLL",
    "NTDLL.DLL",
]

FUNCS = [
    # NATIVE APIS
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

    # WINAPIS
    "CheckRemoteDebuggerPresent",
    "CloseHandle",
    "CreateThreadpoolWait",
    "DllMain",
    "GetProcAddress",
    "IsDebuggerPresent",
    "LoadLibraryA",
    "LoadLibraryW",
    "MessageBoxA",
    "QueryFullProcessImageNameW",
    "RtlAddFunctionTable",
    "SetFileInformationByHandle",
    "SetThreadpoolWait",
    "VirtualAlloc",
    "VirtualProtect",
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

    for mod in MODULES:
        hash_value = calc_hash(mod)
        hash_fmt = f"{'0x{0:x}'.format(hash_value)}"
        # Check if the hash is duplicate
        if is_dupl(hashes, hash_fmt) is True:
            print("The calculated hash is duplicate. Please try again.")
            return
        hashes[f"#define HASH_MODULE_{mod.upper().replace('.DLL', '')}"] = hash_fmt

    for func in FUNCS:
        hash_value = calc_hash(func)
        hash_fmt = f"{'0x{0:x}'.format(hash_value)}"
        # Check if the hash is duplicate
        if is_dupl(hashes, hash_fmt) is True:
            print("The calculated hash is duplicate. Please try again.")
            return
        hashes[f"#define HASH_FUNC_{func.upper()}"] = hash_fmt

    max_length = max(len(api_name) for api_name in hashes.keys())

    for api_name, api_hash in hashes.items():
        print(f"{api_name.ljust(max_length)} {api_hash}")


if __name__ == "__main__":
    print("Set the following defines to a header file such as 'procs.hpp'.\n")
    main()
