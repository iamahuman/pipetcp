# no-ident: workaround MinGW issue ident section duplication
MINGW_EXTRACFLAGS = -fno-ident
MINGW_EXTRALDFLAGS = -Wl,--gc-sections -Wl,--unique=.ident

ifeq ($(USE32),$(if $(USE32),0))
CROSSPREFIX ?= x86_64-w64-mingw32-
O ?= amd64/
LDFLAGS64 ?= -Wl,--high-entropy-va
LDFLAGS_ARCH = $(LDFLAGS64)
else
CROSSPREFIX ?= i686-w64-mingw32-
O ?= x86/
LDFLAGS_ARCH = $(LDFLAGS32)
endif

CC = $(CROSSPREFIX)gcc
WINDRES = $(CROSSPREFIX)windres

CFLAGS = -Wall -Wextra -g -O2 $(MINGW_EXTRACFLAGS) $(EXTRACFLAGS)
LDFLAGS = -municode -mconsole -Wl,--tsaware -Wl,--nxcompat -Wl,--dynamicbase $(MINGW_EXTRALDFLAGS) $(EXTRALDFLAGS) $(LDFLAGS_ARCH)
LIBS = -lkernel32 -ladvapi32 -lws2_32

all: $(O)pipetcp.exe

$(O)pipetcp.exe: $(O)pipetcp.o $(O)rsrc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

$(O)pipetcp.o: pipetcp.c list.h ring.h errors.h udm.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(O)rsrc.o: pipetcp.rc
	$(WINDRES) --output-format=coff -o $@ $<

clean:
	@rm -f $(O)pipetcp.exe $(O)pipetcp.o $(O)rsrc.o

.PHONY: all clean