/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "key_ladder.h"
#include "printf.h"
#include "registers.h"
#include "rescue.h"
#include "rom_uart.h"
#include "setup.h"
#include "signed_header.h"
#include "spiflash.h"
#include "system.h"
#include "trng.h"
#include "verify.h"

extern uint32_t hash[SHA256_DIGEST_WORDS];

/* Returns 1 if image a is newer, 0 otherwise. */
int is_newer_than(const struct SignedHeader *a, const struct SignedHeader *b)
{
	if (a->epoch_ != b->epoch_)
		return a->epoch_ > b->epoch_;
	if (a->major_ != b->major_)
		return a->major_ > b->major_;
	if (a->minor_ != b->minor_)
		return a->minor_ > b->minor_;
	/* This comparison is not made by ROM. */
	if (a->timestamp_ != b->timestamp_)
		return a->timestamp_ > b->timestamp_;

	return 1; /* All else being equal, consider A to be newer. */
}

/* Returns 1 if we should rollback to the older RW image. */
int should_rollback(void)
{
	uint32_t scratch = GREG32(PMU, LONG_LIFE_SCRATCH0);
	uint32_t rollback = scratch & 0xf; // Check the bottom 4 bits.

	debug_printf("retry|%u\n", rollback);

	if (rollback != 0xf) {
		GREG32(PMU, LONG_LIFE_SCRATCH_WR_EN) = 1;
		G32PROT(PMU, LONG_LIFE_SCRATCH0, scratch + 1);
		G32PROT(PMU, LONG_LIFE_SCRATCH_WR_EN, 0);
	}

	if (rollback <= 5)
		return 0;

	return 1;
}

int main(void)
{
	const struct SignedHeader *a, *b, *first, *second, *me;
	uint32_t ladder[SHA256_DIGEST_WORDS];
	int i, mode, count;
	char letter;


	init_cpu();
	init_reg_table();
	
	/* Hold the EC in reset if this is a cold boot */
	if (GREG32(PMU, RSTSRC) & 0xe1) {
		G32PROT_FIELD(PMU, PERICLKSET0, DRBOX0_CLK, 1);
		GREG32(RBOX, ASSERT_EC_RST) = 1;
	}

	reset_cert_ctrls(0xfffffffe);

	/* Do cert #40 and lock in ROM */
	i = key_ladder_step(40, NULL, (uint32_t *)(CONFIG_ROM_BASE + CONFIG_ROM_SIZE));
	while (i) {
		i >>= 1;
		mode++;
	}
	G32PROT(GLOBALSEC, HIDE_ROM, (32 - mode) >> 5);


	/* Print the boot banner. */
	uart_init();
	debug_printf("\nBldr |%u\n", get_cycle_count());


	/* Glitch resist. */
	verify_reg_table(me->err_response_);
	verify_reg_counter(9, me->err_response_);

	set_d_cpu_regions();
	unlockFlashForRW();
	reset_cert_ctrls(0xfffffffe);

	/* Check if dev_mode is pulled high and write an incoming cert over SPI. */
	check_engage_spicert();


	a = (const struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE +
					CONFIG_RW_MEM_OFF);
	b = (const struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE +
					CONFIG_RW_B_MEM_OFF);
	/* Default to loading the older version first.
	 * Run from bank a if the versions are equal.
	 */
	if (is_newer_than(a, b)) {
		first = a;
		second = b;
	} else {
		first = b;
		second = a;
	}
	
	if (should_rollback()) {
		/* Launch from the alternate bank first.
		 * This knob will be used to attempt to load the newer version
		 * after an update and to run from bank b in the face of flash
		 * integrity issues.
		 */
		a = first;
		first = second;
		second = a;
	}

	reset_cert_ctrls(0xfffffffe);
	count = increment_reg_counter();

	LOADERKEY_seed_warmboot(ladder);
	tryLaunch((uint32_t)first, CONFIG_RW_SIZE, ladder);

	/* Reset the register counter going into the next image. */
	set_reg_counter(count);

	tryLaunch((uint32_t)second, CONFIG_RW_SIZE, ladder);
	
	/* If we're still here, we couldn't boot an image. Fall in to rescue mode. */
	debug_printf("No valid RW image found.\n");
	rescue_sync(0);

	do
		letter = read_uart_rx_data();
	while (letter != 'r');

	rescue(NULL);

	/* If we've returned from rescue, reset the chip in hopes 
	 * the next boot succeeds. 
	 */
	system_reset(0x3c);
}

/* Entrypoint for RO. */
void reset(void)
{
	memset(hash, 0, sizeof(hash));
	main();
}