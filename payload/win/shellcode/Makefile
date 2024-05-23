CCX64 = x86_64-w64-mingw32-g++
CCX86 = i686-w64-mingw32-g++

CFLAGS = -Os -masm=intel -nostdlib
CFLAGS += -s -ffunction-sections -fno-ident -fno-asynchronous-unwind-tables -w
CFLAGS += -fpack-struct=8 -falign-labels=1 -falign-jumps=1 -fPIC
CFLAGS += -Wl,-Tscript/linker.ld
CFLAGS += -Wl,-s,--no-seh,--enable-stdcall-fixup

MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT) -DLISTENER_PATH=\"$(LISTENER_PATH)\"

SOURCE = src/core/*.cpp src/entry.cpp

OUTTEMP = build/tmp.exe
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