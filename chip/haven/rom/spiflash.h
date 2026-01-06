/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */
#include "sha256.h"

struct bootstrap_pkt {
	uint8_t hash[SHA256_DIGEST_SIZE];
	uint32_t frame_num;
	uint32_t flash_offset;
	uint8_t data[0];
};

enum bootstrap_err {
    BOOTSTRAP_SUCCESS = 0,
    BOOTSTRAP_NO_DATA = 1,
    BOOTSTRAP_BAD_MAGIC = 2,
    BOOTSTRAP_OVERSIZED_IMAGE = 3,
    BOOTSTRAP_BAD_ADDR,
    BOOTSTRAP_FLASH_WIPE_ERROR = 13,
};


/* Check if Bootstrap is being requested. */
void check_engage_spiflash(void);