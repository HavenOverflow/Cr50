# -*- makefile -*-
# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Board specific files build
#

CHIP:=host

board-y=board.o
board-$(HAS_TASK_CHIPSET)+=chipset.o
board-$(CONFIG_FANS)+=fan.o


# This file is included twice by the Makefile, once to determine the CHIP info
# and then again after defining all the CONFIG_ and HAS_TASK variables. We use
# a guard so that recipe definitions and variable extensions only happen the
# second time.

all: hex

# For the benefit of the tpm2 library.
INCLUDE_ROOT := $(abspath ./include)
CFLAGS += -I$(INCLUDE_ROOT)
CPPFLAGS += -I$(abspath ./builtin)
CPPFLAGS += -I$(abspath ./chip/$(CHIP))
# For core includes
CPPFLAGS += -I$(abspath .)
CPPFLAGS += -I$(abspath $(BDIR))
CPPFLAGS += -I$(abspath ./fuzz)
CPPFLAGS += -I$(abspath ./test)
