/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_LOADER_SETUP_H
#define __EC_CHIP_G_LOADER_SETUP_H

#include <stddef.h>
#include <stdint.h>

#include "dcrypto.h"
#include "timer.h"

struct header_hashes {
	uint32_t img_hash[SHA256_DIGEST_WORDS];
	uint32_t fuses_hash[SHA256_DIGEST_WORDS];
	uint32_t info_hash[SHA256_DIGEST_WORDS];
};

void disarmRAMGuards(void);
int is_dev_loader(uint32_t keyid);
void tryLaunch(uint32_t adr, size_t max_size, uint32_t *ladder);
void unlockFlashForRW(void);
int resetProtections(uint32_t prot_info);
int set_err_response(uint32_t err_resp);
int set_cpu_regions(void);
uint32_t increment_first_ram_word(void);
void set_first_ram_word(int word);
timestamp_t get_time(void);
unsigned int get_cycle_count(void);
unsigned int cycled_trng(void);
int sync_expr(uint32_t expr);
void init_ram(void);
void init_cpu(void);
int verify_err_resp(int expected, int arg2);

#endif /* __EC_CHIP_G_LOADER_SETUP_H */
