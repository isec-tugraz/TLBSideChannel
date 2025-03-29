CC := gcc

SOURCES := $(wildcard *.c)

TARGETS := $(SOURCES:.c=.elf)

CFLAGS += -g
CFLAGS += -O2
CFLAGS += -static
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-pointer-to-int-cast
CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -I../include
CFLAGS += -pthread

all: $(TARGETS)

%.elf: %.c
	$(CC) $< $(CFLAGS) -o $@

clean:
	rm -f *.elf
