/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "debug_printf.h"
#include "link_defs.h"
#include "registers.h"
#include "setup.h"
#include "timer.h"

void unlockFlashForRW(void)
{
	uint32_t text_end = ((uint32_t)(&__data_lma_start) +
				 (uint32_t)(&__data_end) -
				 (uint32_t)(&__data_start) +
				 CONFIG_FLASH_BANK_SIZE)
		& ~(CONFIG_FLASH_BANK_SIZE - 1);

	GREG32(GLOBALSEC, FLASH_REGION1_BASE_ADDR) = text_end;
	GREG32(GLOBALSEC, FLASH_REGION1_SIZE) =
		CONFIG_FLASH_SIZE - text_end - 1;
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, EN, 1);
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, RD_EN, 1);
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, WR_EN, 0);
}

void disarmRAMGuards(void)
{
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION0_CTRL, EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION0_CTRL, RD_EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION0_CTRL, WR_EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION1_CTRL, EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION1_CTRL, RD_EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_D_REGION1_CTRL, WR_EN, 1);
}

int resetProtections(uint32_t prot_info)
{
	GREG32(KEYMGR, CERT_REVOKE_CTRL0) = 0x3fc303c;

	if (!prot_info)
		GREG32(FLASH, FSH_PROTECT_INFO1) = 1;

	GREG32(PMU, RST0_WR_EN) = 0;
	GREG32(PMU, RST1_WR_EN) = 0;
	return GREG32(PMU, RST1_WR_EN);
}

int set_err_response(uint32_t err_resp)
{
	if (err_resp == 3) {
		uint32_t resp = GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
		GREG32(CRYPTO, WIPE_SECRETS) = 0xffffffff;
		GREG32(KEYMGR, AES_WIPE_SECRETS) = 0xffffffff;
		GREG32(KEYMGR, FLASH_RCV_WIPE) = 0xffffffff;

		if (resp & 0x2000) {
			GREG32(GLOBALSEC, CPU0_I_REGION0_CTRL) = 0;
			GREG32(GLOBALSEC, FLASH_REGION0_CTRL) = 0;
			GREG32(GLOBALSEC, FLASH_REGION7_CTRL) = 0;
		}

		if (resp & 0x4000) {
			GREG32(GLOBALSEC, ALERT_DLYCTR0_EN0) = 0x80000;
			GREG32(GLOBALSEC, ALERT_DLYCTR0_LEN) = 1;
			GREG32(GLOBALSEC, ALERT_FW_TRIGGER) = 0xa9;
		}

		if (resp & 0x8000) {
			GREG32(GLOBALSEC, CPU0_I_REGION6_CTRL) = 1;
			GREG32(GLOBALSEC, ALERT_DLYCTR0_EN0) = 0x80000;
			GREG32(GLOBALSEC, ALERT_DLYCTR0_LEN) = 1;
			GREG32(GLOBALSEC, ALERT_FW_TRIGGER) = 0xa9;
		}

		if (resp & 0x1000) {
			int i;

			do {
				i = GREG32(GLOBALSEC, CPU0_S_PERMISSION);
				GREG32(GLOBALSEC, DDMA0_PERMISSION) = 0;
				GREG32(GLOBALSEC, CPU0_S_DAP_PERMISSION) = 0;
				GREG32(GLOBALSEC, CPU0_S_PERMISSION) = 0;
			} while (i != 0x33);
		}
	}

	if ((err_resp - 2) > 1)
		return err_resp - 2;

	while (true)
		;
}

int set_cpu_regions(void)
{
	uint32_t r1, r2, r3;
	uint32_t r1_1, r2_1, r3_1;
	uint32_t r1_2, r2_2, r3_2;
	uint32_t r1_3, r2_3, r3_3;
	memcpy((uint32_t *)0x1188c, "\x5a\xa5\xaa\x55\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\xa5\x5a\x55\xaa", SHA256_DIGEST_SIZE);
	r1 = *(uint32_t*)0x11890;
	r2 = *(uint32_t*)0x11894;
	r3 = *(uint32_t*)0x11898;
	*(uint32_t*)0x10808 = *(uint32_t*)0x1188c;
	*(uint32_t*)0x1080c = r1;
	*(uint32_t*)0x10810 = r2;
	*(uint32_t*)0x10814 = r3;
	r1_1 = *(uint32_t*)0x118a0;
	r2_1 = *(uint32_t*)0x118a4;
	r3_1 = *(uint32_t*)0x118a8;
	*(uint32_t*)0x10818 = *(uint32_t*)0x1189c;
	*(uint32_t*)0x1081c = r1_1;
	*(uint32_t*)0x10820 = r2_1;
	*(uint32_t*)0x10824 = r3_1;
	r1_2 = *(uint32_t*)0x1080c;
	r2_2 = *(uint32_t*)0x10810;
	r3_2 = *(uint32_t*)0x10814;
	*(uint32_t*)0x10648 = *(uint32_t*)0x10808;
	*(uint32_t*)0x1064c = r1_2;
	*(uint32_t*)0x10650 = r2_2;
	*(uint32_t*)0x10654 = r3_2;
	r1_3 = *(uint32_t*)0x1081c;
	r2_3 = *(uint32_t*)0x10820;
	r3_3 = *(uint32_t*)0x10824;
	*(uint32_t*)0x10658 = *(uint32_t*)0x10818;
	*(uint32_t*)0x1065c = r1_3;
	*(uint32_t*)0x10660 = r2_3;
	*(uint32_t*)0x10664 = r3_3;
	GREG32(GLOBALSEC, CPU0_D_REGION0_BASE_ADDR) = 0x10648;
	GREG32(GLOBALSEC, CPU0_D_REGION0_SIZE) = SHA256_DIGEST_SIZE - 1;
	GREG32(GLOBALSEC, CPU0_D_REGION0_CTRL) = 1;
	GREG32(GLOBALSEC, CPU0_D_REGION1_BASE_ADDR) = 0x10808;
	GREG32(GLOBALSEC, CPU0_D_REGION1_SIZE) = SHA256_DIGEST_SIZE - 1;
	GREG32(GLOBALSEC, CPU0_D_REGION1_CTRL) = 1;
	GREG32(GLOBALSEC, CPU0_D_REGION2_BASE_ADDR) = 0x1188c;
	GREG32(GLOBALSEC, CPU0_D_REGION2_SIZE) = SHA256_DIGEST_SIZE - 1;
	GREG32(GLOBALSEC, CPU0_D_REGION2_CTRL) = 1;
	return REG32(0x40090008);
}

uint32_t increment_first_ram_word(void)
{
	uint32_t result = *(uint32_t *)CONFIG_RAM_BASE + 1;
	*(uint32_t *)CONFIG_RAM_BASE = result;
	return result;
}

void set_first_ram_word(int word)
{
	*(uint32_t *)CONFIG_RAM_BASE = word;
}

unsigned int get_cycle_count(void)
{
	return GREG32(M3, DWT_CYCCNT);
}

unsigned int cycled_trng(void)
{
	return (get_cycle_count() + GREG32(TRNG, READ_DATA));
}

uint32_t counter;

int sync_expr(uint32_t expr)
{
	// TODO: The disassembly for this kinda sucks, figure that out
	/*uint32_t rand, i, err_resp = 0;
	rand = cycled_trng();
	GREG32(XO, CLK_JTR_SYNC_CONTENTS) = 0;

	if (counter) {
		do {
			rand = (rand + 0xd3) % counter;

			
			if ((**(uint32_t**)(0x10000 + ((rand + 0xca) << 2)) ^ 0x34687195) != *(uint32_t*)(0x10000 + ((rand + 2) << 2))) {
				debug_printf("!exp @%8x: %x vs. %x\n");
				err_resp = GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
				GREG32(PMU, PWRDN_SCRATCH28) = *(uint32_t*)(0x10000 + ((rand + 0xca) << 2));
				GREG32(PMU, PWRDN_SCRATCH29) = 4;
				set_err_response((err_resp >> 2 & 3) | expr);
			}

			i++;
			counter = *(uint32_t*)0x10004;
		} while (counter > i);
	}*/

	return increment_first_ram_word();
}

void init_ram(void)
{
	uint32_t r3 = *(uint32_t*)0x10004;

	if (r3 <= 0xc7) {
		uint32_t *i = (uint32_t *)(0x10000 + ((r3 + 2) << 2));

		do {
			i[0xc8] = 0xffffffff;
			*(uint32_t*)i = 0;
			i = &i[1];
		} while (i != (uint32_t *)0x10328);
	}
}

void init_cpu(void)
{
	GREG32(M3, DEMCR) |= 0x1000000;
	GREG32(M3, DWT_CTRL) |= 1;
	*(uint32_t*)0x118ac = 0;
}

int verify_err_resp(int expected, int arg2)
{
	int cur_resp = GREG32(FUSE, FW_DEFINED_BROM_ERR_RESPONSE);
	int counter = *(uint32_t *)CONFIG_RAM_BASE;

	if (counter != expected) {
		GREG32(PMU, PWRDN_SCRATCH28) = expected | counter << 0x10;
		GREG32(PMU, PWRDN_SCRATCH29) = 5;
		set_err_response((cur_resp >> 2 & 3) | arg2);
	}

	return increment_first_ram_word();
}