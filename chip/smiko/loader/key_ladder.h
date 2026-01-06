/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_LOADER_KEY_LADDER_H
#define __EC_CHIP_G_LOADER_KEY_LADDER_H

#include <stdint.h>
#include <stddef.h>

int key_ladder_step(uint32_t cert, void *unused, const uint32_t *input);

#endif  /* ! __EC_CHIP_G_LOADER_KEY_LADDER_H */
