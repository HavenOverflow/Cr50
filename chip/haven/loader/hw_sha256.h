/* Copyright 2015 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_ROM_HW_SHA256_H
#define __EC_CHIP_G_ROM_HW_SHA256_H

#include <inttypes.h>
#include <stddef.h>

#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_WORDS (SHA256_DIGEST_LENGTH / sizeof(uint32_t))

void hwSHA256(const void *data, size_t len, uint32_t *digest);

#endif  /* __EC_CHIP_G_ROM_HW_SHA256_H */