# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This is heavily integrated with Smiko's build system, 
# so compiling it by itself may not work.

include $(REPO_ROOT)/toolchain.mk
include $(REPO_ROOT)/sources.mk

ifeq ($(VERBOSE),)
Q := @
else
Q := 
endif

# maybe rely on `../../` instead of `$(REPO_ROOT)`?
CR50_ROOT := $(REPO_ROOT)/src/cr50

VPATH := $(CR50_ROOT)/util
BOARD := cr50

LIBS_DIR := $(REPO_ROOT)/lib
BDIR := $(REPO_ROOT)/build/gsctool/$(ARCH)
ODIR := $(REPO_ROOT)/build/bin/$(ARCH)
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

CFLAGS  += -I$(CR50_ROOT)/include -I$(CR50_ROOT)/util -I$(CR50_ROOT)/fuzz -I$(CR50_ROOT)/test -I$(REPO_ROOT)/lib/$(ARCH)/openssl/include
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

CPPFLAGS  += -I$(CR50_ROOT)/board/cr50 -I $(CR50_ROOT)/chip/smiko

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
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -c -MMD -MF $(basename $@).d $(LIBS_CFLAGS) -o $@ $<

$(BDIR)/gsctool.o:  generated_version.h

generated_version.h: $(GSCTOOL_SOURCES)
	# Make sure ${BOARD} not set to anything when invoking getversion.sh,
	# as even when building with Cr50 enabled, other directories do not
	# matter for gsctool.
	@echo "  VERSION $@"
	$(Q)(cd $(CR50_ROOT)/; BOARD= util/getversion.sh) > $@

.PHONY: clean

dp: CFLAGS += -O0
dp: desc_parser.c
	$(Q)$(CC) $(CFLAGS) $(CPPFLAGS) -DTEST_PARSER -MMD -MF $(basename $@).d desc_parser.c -o $@

-include $(DEPS)
