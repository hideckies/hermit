MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT) -DLISTENER_PATH=\"$(LISTENER_PATH)\"

OBJFILE = build/shellcode.o
OUTFILE = ${OUTPUT}

_remake-builddir:
	@ rm -rf build
	@ mkdir -p build

# _objccopy:
# 	@ objcopy -O binary $(OBJFILE) $(OUT_FILE)

x64:
	@ $(MAKE) _remake-builddir
	@ nasm -f win64 -o ${OBJFILE}
	@ link /SUBSYSTEM:WINDOWS /ENTRY:_start ${OBJFILE} /OUT:${OUTFILE}

# x86:
# 	@ $(MAKE) _remake-builddir
# 	# @ nasm -f win32 -o $(OBJ_FILE) src/asm/win/x86/main.sm
# 	# @ make _objcopy
# 	@ nasm -f bin -o $(OUT_FILE) src/asm/win/x86/main.asm

.PHONY: clean
clean:
	@ rm -f build
