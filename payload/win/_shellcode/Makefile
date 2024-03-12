MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT) -DLISTENER_PATH=\"$(LISTENER_PATH)\"

OBJ_FILE = build/shellcode.o
OUT_FILE = ${OUTPUT}

_remake-builddir:
	@ rm -rf build
	@ mkdir -p build

_objccopy:
	@ objcopy -O binary $(OBJ_FILE) $(OUT_FILE)

linux-x64:
	@ $(MAKE) _remake-builddir
	@ nasm -f bin -o $(OUT_FILE) src/asm/linux/x64/main.asm

linux-x86:
	@ $(MAKE) _remake-builddir
	@ nasm -f bin -o $(OUT_FILE) src/asm/linux/x86/main.asm

win-x64:
	@ $(MAKE) _remake-builddir
	# @ nasm -f win64 -o $(OBJ_FILE) src/asm/win/x64/main.asm
	# @ ld -m elf_x86_64 -o tmp/tmp $(OBJ_FILE)
	# @ make _objcopy
	@ nasm -f bin -o $(OUT_FILE) src/asm/win/x64/main.asm

win-x86:
	@ $(MAKE) _remake-builddir
	# @ nasm -f win32 -o $(OBJ_FILE) src/asm/win/x86/main.sm
	# @ make _objcopy
	@ nasm -f bin -o $(OUT_FILE) src/asm/win/x86/main.asm

.PHONY: clean
clean:
	@ rm -f build
