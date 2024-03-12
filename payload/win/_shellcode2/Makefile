CCX64 = x86_64-w64-mingw32-g++
CCX86 = i686-w64-mingw32-g++

CFLAGS =  -Os -s -w -nostdlib
CFLAGS += -fno-asynchronous-unwind-tables
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS += -ffunction-sections -falign-jumps=1
CFLAGS += -falign-labels=1 -fPIC
CFLAGS += -Wl,-TScripts/Linker.ld
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup

SOURCE = src/*.cpp

OUT_ASM = build/shellcode.s
OUT_EXE = build/shellcode.exe
OUT_OBJ = build/shellcode.o
OUT_RAW = ${OUTPUT}

INCLUDE = ./include

# MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT) -DLISTENER_PATH=\"$(LISTENER_PATH)\"

_remake-builddir:
	@ mkdir -p build
	@ rm -rf build/*

# _objccopy:
# 	@ objcopy -O binary $(OBJ_FILE) $(OUT_FILE)

linux-x64:
	@ ${MAKE} _remake-builddir
	@ ${CCX64} ${SOURCE} -o ${OUT_ASM} ${CFLAGS} -I${INCLUDE}

linux-x86:
	@ ${MAKE} _remake-builddir
	@ ${CCX86} ${SOURCE} -o ${OUT_ASM} ${CFLAGS} -I${INCLUDE}

win-x64:
	@ ${MAKE} _remake-builddir
	@ nasm -f win64 src/mainx64.asm -o ${OUT_OBJ}
	@ ${CCX64} ${SOURCE} ${OUT_OBJ} -o ${OUT_EXE} ${CFLAGS} -I${INCLUDE} -masm=intel
	# Extract shellcode from executable
	@ python3 scripts/extract.py -f ${OUT_EXE} -o ${OUT_RAW}

win-x86:
	@ ${MAKE} _remake-builddir
	@ ${CCX86} ${SOURCE} -o ${OUT_ASM} ${CFLAGS} -I${INCLUDE} -masm=intel

.PHONY: clean
clean:
	@ rm -rf build/*
