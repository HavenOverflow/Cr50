/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "board_config.h"
#include "registers.h"
#include "scratch_reg1.h"

void chip_pre_init(void)
{
	/*
	 * If we're resuming from deep sleep we need to undo some stuff as soon
	 * as possible and this is the first init function that's called.
	 *
	 * It doesn't hurt anything if this setup is not needed, but we don't
	 * investigate the reset cause until much later (and doing so is
	 * destructive), so we'll just do the post-deep-sleep setup every time.
	 */

	/* Disable the deep sleep triggers */
	GR_PMU_LOW_POWER_DIS = 0;
	GR_PMU_EXITPD_MASK = 0;

	/* Unfreeze the USB module */
	GWRITE_FIELD(USB, PCGCCTL, STOPPCLK, 0);
	GWRITE_FIELD(USB, PCGCCTL, RSTPDWNMODULE, 0);
	GWRITE_FIELD(USB, PCGCCTL, PWRCLMP, 0);

	/* Let's enable UART for the RO. */
	if (GREG32(PMU, LONG_LIFE_SCRATCH1) & BOARD_NO_RO_UART) {
		GWRITE_FIELD(PMU, LONG_LIFE_SCRATCH_WR_EN, REG1, 1);
		GREG32(PMU, LONG_LIFE_SCRATCH1) &= ~BOARD_NO_RO_UART;
		GWRITE_FIELD(PMU, LONG_LIFE_SCRATCH_WR_EN, REG1, 0);
	}
}
