/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "debug_printf.h"
#include "registers.h"
#include "regtable.h"
#include "setup.h"
#include "timer.h"

void unlockFlashForRW(void)
{
	G32PROT(GLOBALSEC, FLASH_REGION1_BASE_ADDR, text_end);
	G32PROT(GLOBALSEC, FLASH_REGION1_SIZE,
		CONFIG_FLASH_SIZE - text_end - 1);
	G32PROT(GLOBALSEC, FLASH_REGION1_CTRL, 3);
}

void reset_cert_ctrls(int prot_info)
{
	GREG32(KEYMGR, CERT_REVOKE_CTRL0) = 0x3fc303c;

	if (!prot_info)
		GREG32(FLASH, FSH_PROTECT_INFO1) = 1;

	G32PROT(PMU, RST0_WR_EN, 0);
	G32PROT(PMU, RST1_WR_EN, 0);
}

void disarmRAMGuards(void)
{
	G32PROT(GLOBALSEC, CPU0_D_REGION0_CTRL, 7);
	G32PROT(GLOBALSEC, CPU0_D_REGION1_CTRL, 7);
	G32PROT(GLOBALSEC, CPU0_D_REGION2_CTRL, 7);
}

void set_cpu_d_regions(void)
{
	static uint32_t region0[SHA256_DIGEST_WORDS]; // 0x10648
	static uint32_t region1[SHA256_DIGEST_WORDS]; // 0x10808
	static uint32_t region2[SHA256_DIGEST_WORDS]; // 0x1188c

	GREG32(GLOBALSEC, CPU0_D_REGION0_BASE_ADDR) = region0;
	GREG32(GLOBALSEC, CPU0_D_REGION0_SIZE) = SHA256_DIGEST_SIZE - 1;
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION0_CTRL, EN, 1);
	GREG32(GLOBALSEC, CPU0_D_REGION1_BASE_ADDR) = region1;
	GREG32(GLOBALSEC, CPU0_D_REGION1_SIZE) = SHA256_DIGEST_SIZE - 1;
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION1_CTRL, EN, 1);
	GREG32(GLOBALSEC, CPU0_D_REGION2_BASE_ADDR) = region2;
	GREG32(GLOBALSEC, CPU0_D_REGION2_SIZE) = SHA256_DIGEST_SIZE - 1;
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION2_CTRL, EN, 1);
}

void init_cpu(void)
{
	GWRITE_FIELD(M3, DEMCR, TRCENA, 1);
	/* Enable CPU cycle count incrementation. */
	GWRITE_FIELD(M3, DWT_CTRL, CYCCNTENA, 1);

	REG32(0x118ac) = 0;
}
