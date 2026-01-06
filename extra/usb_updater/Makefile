# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

include ../../../../toolchain.mk

ARCH ?= x86_64

CFLAGS  += -std=gnu99 \
	-Wall \
	-Werror \
	-Wpointer-arith \
	-Wcast-align \
	-Wcast-qual \
	-Wundef \
	-Wsign-compare \
	-Wredundant-decls \
	-Wmissing-declarations

ifeq ($(VERBOSE),)
Q := @
else
Q := 
endif

VPATH = ../../util
BOARD := cr50

LIBS_DIR := ../../../../lib
BDIR := ../../../../build/gsctool/$(ARCH)
ODIR := ../../../../build/bin/$(ARCH)
PROGRAMS := $(ODIR)/gsctool

CFLAGS_CONFIG := $(shell $(PKG_CONFIG) --cflags libusb-1.0)
CFLAGS_g := $(shell $(PKG_CONFIG) --cflags libcrypto)

ifeq ($(STATIC),)
LIBS_CONFIG := $(shell $(PKG_CONFIG) --libs   libusb-1.0)
LIBS_g  := $(shell $(PKG_CONFIG) --libs libcrypto)
else
LIBS_CONFIG := $(LIBS_DIR)/$(ARCH)/libusb-1.0.a
LIBS_g  := $(LIBS_DIR)/$(ARCH)/libcrypto.a
LDFLAGS += -static
endif

CFLAGS  += -I../../include -I../../util -I../../fuzz -I../../test -I../../../../lib/$(ARCH)/openssl/include
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

LIBS    += $(LIBS_CONFIG) $(LIBS_g)
CFLAGS  += $(CFLAGS_CONFIG) $(CFLAGS_g)
CPPFLAGS  += -I../../board/cr50 -I ../../chip/smiko

all: $(PROGRAMS)

GSCTOOL_SOURCES := gsctool.c desc_parser.c usb_if.c verify_ro.c
GSCTOOL_OBJS := $(patsubst %.c,$(BDIR)/%.o,$(GSCTOOL_SOURCES))
DEPS := $(patsubst %.c,$(BDIR)/%.d,$(GSCTOOL_SOURCES)) dp.d

# chip/g updater
$(ODIR)/gsctool: $(GSCTOOL_OBJS) Makefile
	@echo "  LD      $@"
	$(Q)$(CC) $(CFLAGS) $(GSCTOOL_OBJS) $(LDFLAGS) $(LIBS) -o $@

$(BDIR)/%.o: %.c
	@echo "  CC      $<"
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -c -MMD -MF $(basename $@).d -o $@ $<

$(BDIR)/gsctool.o:  generated_version.h

generated_version.h: $(GSCTOOL_SOURCES)
	# Make sure ${BOARD} not set to anything when invoking getversion.sh,
	# as even when building with Cr50 enabled, other directories do not
	# matter for gsctool.
	@echo "  VERSION $@"
	$(Q)(cd ../../; BOARD= util/getversion.sh) > $@

.PHONY: clean

dp: CFLAGS += -O0
dp: desc_parser.c
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DTEST_PARSER -MMD -MF $(basename $@).d desc_parser.c -o $@

-include $(DEPS)
