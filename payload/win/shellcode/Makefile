CCX64 = x86_64-w64-mingw32-gcc
CCX86 = i686-w64-mingw32-gcc

CFLAGS = -masm=intel -nostdlib
CFLAGS += -ffunction-sections -fno-ident -fno-asynchronous-unwind-tables -w -O2

CFLAGSX64 = $(CFLAGS) -Wl,-e,AlignRSP
CFLAGSX86 = $(CFLAGS) -Wl,-e,Entry

MACROS = -DLISTENER_HOST=\"$(LISTENER_HOST)\" -DLISTENER_PORT=$(LISTENER_PORT) -DLISTENER_PATH=\"$(LISTENER_PATH)\"

SOURCE = src/core/*.cpp src/entry.cpp

OUTTEMP = build/tmp.exe
OUTFILE = ${OUTPUT}

amd64: clean
	@ $(CCX64) -o $(OUTTEMP) $(CFLAGSX64) -Iinclude $(SOURCE)
	@ objcopy -O binary --only-section=.text $(OUTTEMP) $(OUTFILE)

i686: clean
	@ $(CCX86) -o $(OUTTEMP) $(CFLAGSX86) -Iinclude $(SOURCE)
	@ objcopy -O binary --only-section=.text $(OUTTEMP) $(OUTFILE)

clean:
	@ rm -rf build/*