from typing import Mapping

APIS = [
    # NATIVE APIS
    "LdrLoadDll",
    "NtFlushInstructionCache",
    "NtCreateProcessEx",
    "NtOpenProcess",
    "NtOpenProcessToken",
    "NtTerminateProcess",
    "NtQueryInformationProcess",
    "NtSetInformationProcess",
    "NtCreateThreadEx",
    "NtOpenThread",
    "NtResumeThread",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtAllocateVirtualMemory",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtFreeVirtualMemory",
    "NtDuplicateObject",
    "NtWaitForSingleObject",
    "NtClose",
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtDeleteFile",
    "NtCreateNamedPipeFile",
    "NtQueryInformationFile",
    "NtSetInformationFile",
    "NtQueryInformationToken",
    "NtQuerySystemInformation",
    "NtSystemDebugControl",
    "NtPrivilegeCheck",
    "NtAdjustPrivilegesToken",
    "NtOpenKeyEx",
    "NtQueryKey",
    "NtEnumerateValueKey",
    "NtUnmapViewOfSection",
    # NATIVE APIS (RUNTIME LIBRARY)
    "RtlAllocateHeap",
    "RtlZeroMemory",
    "RtlInitUnicodeString",
    "RtlStringCchCatW",
    "RtlStringCchCopyW",
    "RtlStringCchLengthW",
    "RtlQuerySystemInformation",
    "RtlExpandEnvironmentStrings",
    "RtlGetCurrentDirectory_U",
    "RtlSetCurrentDirectory_U",
    "RtlGetFullPathName_U",
    # WINAPIS
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "CreateThreadpoolWait",
    "SetThreadpoolWait",
    "WinHttpOpen",
    "QueryFullProcessImageNameW",
    "RtlAddFunctionTable",
    "DllMain",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "CloseHandle",
    "SetFileInformationByHandle",
    "MessageBoxA",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSetOption",
    "WinHttpSendRequest",
    "WinHttpWriteData",
    "WinHttpReceiveResponse",
    "WinHttpQueryHeaders",
    "WinHttpQueryDataAvailable",
    "WinHttpReadData",
    "WinHttpCloseHandle"
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
    for api in APIS:
        hash_value = calc_hash(api)
        hash_fmt = f"{'0x{0:x}'.format(hash_value)}"

        # Check if the hash is duplicate
        if is_dupl(hashes, hash_fmt) is True:
            print("The calculated hash is duplicate. Please try again.")
            return
    
        hashes[f"#define APIHASH_{api.upper()}"] = hash_fmt

    max_length = max(len(api_name) for api_name in hashes.keys())

    for api_name, api_hash in hashes.items():
        print(f"{api_name.ljust(max_length)} {api_hash}")


if __name__ == "__main__":
    print("Set the following defines to a header file such as 'procs.hpp'.\n")
    main()
