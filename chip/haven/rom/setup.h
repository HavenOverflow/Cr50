/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_LOADER_SETUP_H
#define __EC_CHIP_G_LOADER_SETUP_H

#include <stddef.h>
#include <stdint.h>

#include "hw_sha256.h"
#include "signed_header.h"

void disarmRAMGuards(void);
void unlockFlashForRW(void);
void set_cpu_d_regions(void);
void disarmRAMGuards(void);
void unlockINFO1(void);
void unlockFlashForRO(void);
void check_engage_spiflash(void);

void init_cpu(void);
int cpu_setup(void);
int init_parity(void);
int init_gpio(void);
int init_power(void);
int init_clock(int ret);
int init_trng(void);

void boot_sys(uint32_t adr, size_t max_size);
void apply_header_security(const struct SignedHeader *hdr);
int is_newer_than(const struct SignedHeader *a, const struct SignedHeader *b);

void _purgatory(int level);
int is_known_key(uint32_t keyid);
int rand(void);

#endif  /* __EC_CHIP_G_LOADER_SETUP_H */
