/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "regtable.h"
#include "setup.h"
#include "signed_header.h"

int main(void)
{
	const struct SignedHeader *a, *b;
	uint32_t scratch, counter, resp, ret;

	init_regtable();
	init_cpu();

	resp = G32PROT_VAL(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
	G32PROT_FIELD(GLOBALSEC, ALERT_CONTROL, PROC_LOCKUP_SHUTDOWN_EN, (resp >> 0xa & 3));

	ret = cpu_setup();

	scratch = (ret) // 0, 1, 3, 5
            | (init_parity() << 3) // 0, 1
            | (init_gpio() << 6) // 0
            | (init_power() << 9) // 0, 1
            | (init_clock(ret) << 12) // 0, 1, 3, 5
            | (init_trng() << 15); // 0, 1
	GREG32(PMU, PWRDN_SCRATCH31) = scratch;

	/* Print the boot banner. */
	debug_printf("\nHavn2|");
	debug_printf("%8d_%6d@%d\n", GREG32(SWDP, BUILD_DATE), 
		GREG32(SWDP, BUILD_TIME), GREG32(SWDP, P4_LAST_SYNC));

	// _purgatory triggers when cpu_setup_ret is 1, 3, 5, or if init_clock_ret is 3, 5.
	if (scratch & 0x36db6)
		_purgatory(resp & 3);

	set_cpu_d_regions();
	
	/* Unlock flash access. */
	unlockFlashForRO();
	unlockINFO1();

	/* Check if the board wants to bootstrap a new image. */
	check_engage_spiflash();

	/* Protect against glitches. */
	verify_reg_table(0);

	a = (const struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE + 
				CONFIG_RO_MEM_OFF);
	b = (const struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE +
				CHIP_RO_B_MEM_OFF);

	if (is_newer_than(b, a)) {
		counter = increment_reg_counter();
		boot_sys((uint32_t)b, CFG_FLASH_HALF);
		set_reg_counter(counter);
		boot_sys((uint32_t)a, CONFIG_FLASH_SIZE);
	} else{
		counter = increment_reg_counter();
		boot_sys((uint32_t)a, CONFIG_FLASH_SIZE);
		set_reg_counter(counter);
		boot_sys((uint32_t)b, CFG_FLASH_HALF);
	}

	debug_printf("No go :-(\n");

	/* We failed to launch an image. Set the scratch indicator and panic. */
	disarmRAMGuards();
	GREG32(PMU, PWRDN_SCRATCH29) = 1;
	_purgatory((resp & BIT(6)) | 2);
}