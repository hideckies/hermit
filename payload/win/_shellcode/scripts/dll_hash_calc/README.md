# DLL Hash Calculator

This is used for finding the addresses of WinAPI functions.  
These generated hash values are inserted in `.asm` files of shellcode.

## Usage

### 1. Build

1. Open Visual Studio and create a new solution named `DllHashCalc`.  
2. Create `main.cpp` and copy&paste the code of `dll_hash_calc.cpp` into it.  
3. Build the solution.
4. We can get the executable at `DllHashCalc\x64\<Debug or <Release>\DllHashCalc.exe`.

### 2. Run

Run the executable and save results into a file.

```powershell
DllHashCalc.exe C:\\Windows\SysWOW64\kernel32.dll > dll_hashes.txt
```

### 3. Find Hashes

1. Transfer the `dll_hashes.txt` from Windows to Linux (or WSL).
2. Check the charcode of this file.

```sh
file -i dll_hashes.txt
# dll_hashes.txt: text/plain; charset=utf-16le
```

3. Convert the charcode from **UTF-16** to **UTF-8**.

```sh
iconv -f utf-16le -t utf-8 dll_hashes.txt > dll_hashes_utf8.txt
```

4. Find desired function hashes.

```sh
cat dll_hashes_utf8.txt | grep LoadLibraryA
# LoadLibraryA:0x00059ba3
```

## References

- [Red Teaming's Dojo](https://mohamed-fakroud.gitbook.io/red-teamings-dojo/shellcoding/leveraging-from-pe-parsing-technique-to-write-x86-shellcode#id-4.-find-loadlibraya-using-hashed-export-names)
