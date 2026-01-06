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

/* The following file is the main entrypoint for the Cr50 RO firmware
 * that will be verified and loaded by the BootROM. Our job is to lock in the ROM
 * and to verify and launch the Cr50 RW firmware.
 *
 * Decompiled and cleaned up with love by Hannah <3
 */

/* Filler to prevent symbol errors in debug logging. */
timestamp_t get_time(void)
{
	timestamp_t ret;

	ret.val = 0;

	return ret;
}

/* Returns 1 if image a is newer, 0 otherwise. */
int is_newer_than(const struct SignedHeader *a, const struct SignedHeader *b)
{
	if (a->epoch_ != b->epoch_)
		return a->epoch_ > b->epoch_;
	if (a->major_ != b->major_)
		return a->major_ > b->major_;
	if (a->minor_ != b->minor_)
		return a->minor_ > b->minor_;
	if (a->timestamp_ != b->timestamp_)
		return a->timestamp_ > b->timestamp_;

	return 1; /* All else being equal, consider A to be newer. */
}

/* Returns 1 if we should rollback to the older RW image. */
int should_rollback(void)
{
	uint32_t scratch = GREG32(PMU, LONG_LIFE_SCRATCH0);
	uint32_t rollback = scratch & 0xf;

	debug_printf("retry|%u\n", scratch);

	if (rollback != 0xf) {
		GREG32(PMU, LONG_LIFE_SCRATCH_WR_EN) = 1;
		GREG32(PMU, LONG_LIFE_SCRATCH0) += 1;
		GREG32(PMU, LONG_LIFE_SCRATCH_WR_EN) = 0;
	}

	if (rollback <= 5)
		return 0;

	return 1;
}

int main(void)
{
	const struct SignedHeader *a, *b, *first, *second, *ro_a;
	uint32_t ladder[8];
	int i, mode, ram_word;
	char letter;

	init_cpu();
	init_ram();
	
	/* Assert an EC reset if the H1 reset source needs it. */
	if (GREG32(PMU, RSTSRC) & 0xe1) {
		GREG32(PMU, PERICLKSET0) |= 0x400000;
		GREG32(RBOX, ASSERT_EC_RST) = 1;
	}

	resetProtections(-2);

	i = key_ladder_step(40, NULL, (uint32_t *)(CONFIG_ROM_BASE + CONFIG_ROM_SIZE));
	while (i) {
		i >>= 1;
		mode++;
	}
	GREG32(GLOBALSEC, HIDE_ROM) = (32 - mode) >> 5;

	uart_init();
	
	debug_printf("\nBldr |%u\n", get_cycle_count());

	ro_a = (const struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE + CONFIG_RO_MEM_OFF);
	sync_expr(ro_a->err_response_);
	verify_err_resp(9, ro_a->err_response_);

	set_cpu_regions();
	unlockFlashForRW();
	resetProtections(-2);

	/* Check if we need to save anything from SPI to the flash. */
	//check_engage_spiflash(); // TODO: Re-add with SPI flash is finished.


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

	resetProtections(-2);
	ram_word = increment_first_ram_word();

	DCRYPTO_ladder_random(ladder);
	tryLaunch((uint32_t)first, CONFIG_RW_SIZE, ladder);
	set_first_ram_word(ram_word);
	tryLaunch((uint32_t)second, CONFIG_RW_SIZE, ladder);
	
	/* If we're still here, we couldn't boot an image. Fall in to rescue mode. */
	debug_printf("No valid RW image found.\n");
	attempt_sync(0);

	do
		letter = read_uart_rx_data();
	while (letter != 'r');

	rescue(NULL);

	/* If we've returned from rescue, reset the chip in hopes 
	 * the next boot succeeds. 
	 */
	system_reset(0x3c);
}

void interrupt_disable(void)
{
	asm("cpsid i");
}