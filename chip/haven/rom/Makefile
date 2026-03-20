CROSS_COMPILE := arm-none-eabi-

SHELL ?= /bin/sh
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)gcc
OBJCOPY := $(CROSS_COMPILE)objcopy
CP ?= cp
RM ?= rm
MKDIR ?= mkdir
TOUCH ?= touch

ROOT ?= ../../..
BDIR ?= build

# These are the flags used to compile normal binaries throughout src/*.c
CPPFLAGS += -I. -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CFLAGS += -Wall -std=gnu99 -g -Wno-deprecated-declarations -Wno-parentheses \
	-Wno-stringop-overflow -Wno-pointer-sign -Wno-incompatible-pointer-types \
	-Wno-format-extra-args -Wno-format -Wno-array-parameter -Wno-stringop-overread
CFLAGS += -march=armv7-m -mcpu=cortex-m3 -mthumb -Os -mno-sched-prolog -mno-unaligned-access \
		-ffreestanding
CFLAGS += -I.. -I$(ROOT)/include -I$(ROOT)/builtin -I$(ROOT)/board/cr50 \
	-I$(ROOT)/fuzz -I$(ROOT)/test -I$(ROOT)

LDFLAGS += -march=armv7-m -mcpu=cortex-m3 -mthumb -nostartfiles -T rom.lds -nostdlib -nostdinc


PROGS:= $(BDIR)/bootrom.bin
SRCS  = $(BDIR)/boot.o
SRCS += $(BDIR)/debug_printf.o
SRCS += $(BDIR)/flash.o
SRCS += $(BDIR)/hw_sha256.o
SRCS += $(BDIR)/init.o
SRCS += $(BDIR)/main.o
SRCS += $(BDIR)/regtable.o
SRCS += $(BDIR)/rom_uart.o
SRCS += $(BDIR)/setup.o
SRCS += $(BDIR)/spiflash.o
SRCS += $(BDIR)/vectors.o
SRCS += $(BDIR)/verify.o
SRCS += $(BDIR)/pmu.o

# Use VERBOSE=1 for debug output
ifeq ($(VERBOSE),)
Q := @
SUPPRESS := >/dev/null
else
Q :=
SUPPRESS := --verbose
endif

all: $(BDIR) $(PROGS)

.PHONY: clean
clean:
	$(Q)$(RM) -rf build

$(BDIR):
	$(Q)$(MKDIR) -p $@

$(BDIR)/%.o: %.c
	@echo "  CC      $(notdir $<)"
	$(Q)$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

$(BDIR)/%.o: %.S
	@echo "  AS      $(notdir $<)"
	$(Q)$(CC) -c $< -o $@ $(CFLAGS) $(CPPFLAGS)

$(BDIR)/bootrom.elf: $(SRCS)
	@echo "  LD      $(notdir $@)"
	$(Q)$(LD) $^ -o $@ $(LDFLAGS)

$(BDIR)/bootrom.bin: $(BDIR)/bootrom.elf
	@echo "  OBJCOPY $(notdir $@)"
	$(Q)$(OBJCOPY) -O binary $< $@