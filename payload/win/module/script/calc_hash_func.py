from typing import Mapping

FUNCS = [
    # NTAPI
    "LdrLoadDll",
    "NtFlushInstructionCache",
    
    # WINAPI
    "DllMain",
    "GetProcAddress",
    "LoadLibraryA",
    "VirtualAlloc",
    "VirtualProtect",
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
            print("The calculated hash is duplicate. Try aother algorithm.")
            return
        hashes[f"#define HASH_FUNC_{func.upper()}"] = hash_fmt

    max_length = max(len(api_name) for api_name in hashes.keys())

    for api_name, api_hash in hashes.items():
        print(f"{api_name.ljust(max_length)} {api_hash}")


if __name__ == "__main__":
    print("Set the following defines to a header file such as 'procs.hpp'.\n")
    main()
