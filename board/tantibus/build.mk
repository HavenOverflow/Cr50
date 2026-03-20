# -*- makefile -*-
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Board-specific build requirements

# Define the SoC used by this board
CHIP:=dauntless
CHIP_FAMILY:=tantibus
CHIP_VARIANT ?= tantibus_fpga

# Additional / overriding warnings for common rules and chip
# (TODO) enable after https://crrev.com/c/3198155
# CFLAGS_BOARD :=-Wno-array-parameter -Wno-stringop-overread

# This file is included twice by the Makefile, once to determine the CHIP info
# and then again after defining all the CONFIG_ and HAS_TASK variables. We use
# a guard so that recipe definitions and variable extensions only happen the
# second time.
ifeq ($(BOARD_MK_INCLUDED_ONCE),)

BOARD_MK_INCLUDED_ONCE=1
SIG_EXTRA = --cros
else

# Need to generate a .hex file
all: hex

# Objects that we need to build
board-y =  board.o
board-y += wp.o

RW_BD_OUT=$(out)/RW/$(BDIR)

# For core includes
CPPFLAGS += -I$(abspath .)
CPPFLAGS += -I$(abspath $(BDIR))
CPPFLAGS += -I$(abspath ./fuzz)
CPPFLAGS += -I$(abspath ./test)

endif   # BOARD_MK_INCLUDED_ONCE is nonempty
