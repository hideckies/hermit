import argparse
import os
import subprocess

from asm import exec as asm_exec

ASM_FILE = "/tmp/shellcode_generator.asm"
OBJ_FILE = "/tmp/shellcode_generator.o"

def delete_tmp_files():
    if os.path.isfile(ASM_FILE):
        os.remove(ASM_FILE)
    if os.path.isfile(OBJ_FILE):
        os.remove(OBJ_FILE)

def compile_asm(type: str, type_args: str) -> bool:
    asm_code = ""

    if type == "exec":
        asm_code = asm_exec.generate(type_args)

    # Write the assembly code to file.
    with open(ASM_FILE, "w") as f:
        f.write(asm_code)

    # Compile assembly.
    result = subprocess.call(["nasm", "-f", "win64", "-o", OBJ_FILE, ASM_FILE])
    if result != 0:
        return False

    return True

def extract_shellcode() -> bytes:
    # Extract shellcode from object file.
    objdump_output = subprocess.check_output(["objdump", "-D", OBJ_FILE]).decode()

    shellcode_lines = objdump_output.splitlines()
    shellcode = ""
    for line in shellcode_lines:
        if len(line) > 0 and line[0] == ' ':
            shellcode += line.split('\t')[1].replace(" ", "")

    # Convert hex to binary data
    binary_data = bytes.fromhex(shellcode)

    return binary_data

def main():
    parser = argparse.ArgumentParser(description="Shellcode Generator")
    parser.add_argument('-t', '--type', help='Shellcode type e.g. "exec", "dll-loader"')
    parser.add_argument('-c', '--cmd', help='Command name e.g. "calc.exe". This option must be specified for the "exec" type')
    parser.add_argument('-o', '--output', help='Output file')
    args = parser.parse_args()

    if compile_asm(args.type, args.cmd) is False:
        delete_tmp_files()
        return

    binary_data = extract_shellcode()

    # Write to out file
    with open(args.output, "wb") as f:
        f.write(binary_data)

    delete_tmp_files()

if __name__ == "__main__":
    main()
