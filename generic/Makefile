CC := gcc

SOURCES := $(wildcard *.c)

TARGETS := $(SOURCES:.c=.elf)

CFLAGS += -g
CFLAGS += -O3
CFLAGS += -static
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-pointer-to-int-cast
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -I../include
CFLAGS += -pthread

all: $(TARGETS) 

%.elf: %.c ../include/tlb_flush.h ../include/cacheutils.h ../include/ulkm.h ../include/utils.h ../include/coarse_grain_leak.h
	$(CC) $< $(CFLAGS) -o $@

clean:
	rm -f *.elf
