/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "hw_sha256.h"
#include "regtable.h"
#include "flash.h"
#include "setup.h"
#include "signed_header.h"
#include "uart.h"
#include "verify.h"

static int unlockedForExecution(void)
{
	return GREAD_FIELD(GLOBALSEC, SB_COMP_STATUS, SB_BL_SIG_MATCH);
}

void _jump_to_address(const void *addr)
{
	__asm__ volatile("ldr sp, [%0]; \
			ldr pc, [%0, #4];"
			 : : "r"(addr)
			 : "memory");
}

void boot_sys(uint32_t adr, size_t max_size)
{
	static struct {
		uint32_t img_hash[SHA256_DIGEST_WORDS];
		uint32_t fuses_hash[SHA256_DIGEST_WORDS];
		uint32_t info_hash[SHA256_DIGEST_WORDS];
	} hashes;
	static uint32_t hash[SHA256_DIGEST_WORDS];
	static uint32_t fuses[FUSE_MAX];
	static uint32_t info[INFO_MAX];
	uint32_t config1; 
	int i;
	const struct SignedHeader *hdr = (const struct SignedHeader *)(adr);

	/* Zero out the hash buffer. */
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
		hash[i] = 0;

	/* Validity check image header. */
	if (hdr->magic != -1)
		return;
	if (hdr->image_size > max_size)
		return;

	/* Validity checks that image uses known key. */
	if (!is_known_key(hdr->keyid))
		return;

	/* Validity checks that image belongs at adr. */
	if (hdr->ro_base < adr)
		return;
	if (hdr->ro_max > adr + max_size)
		return;
	if (hdr->rx_base < adr)
		return;
	if (hdr->rx_max > adr + max_size)
		return;

	/* Setup candidate execution region 0 based on header information. */
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION0_BASE_ADDR, hdr->rx_base);
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION0_SIZE, 
		hdr->rx_max - hdr->rx_base - 1);
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION0_CTRL, 3);

	hwSHA256((uint8_t *) &hdr->tag,
			hdr->image_size - offsetof(struct SignedHeader, tag),
			hashes.img_hash);
	debug_printf("Himg =%h\n", SHA256_DIGEST_LENGTH, hashes.img_hash);

	/* Sense fuses into RAM array; hash array. */
	for (i = 0; i < FUSE_MAX; ++i)
		fuses[i] = FUSE_IGNORE;

	for (i = 0; i < FUSE_MAX; ++i) {
		/*
		 * For the fuses the header cares about, read their values
		 * into the map.
		 */
		if (hdr->fusemap[i>>5] & (1 << (i&31))) {
			/*
			 * BNK0_INTG_CHKSUM is the first fuse and as such the
			 * best reference to the base address of the fuse
			 * memory map.
			 */
			fuses[i] = GREG32_ADDR(FUSE, BNK0_INTG_CHKSUM)[i];
		}
	}

	hwSHA256((uint8_t *) fuses, sizeof(fuses), hashes.fuses_hash);
	debug_printf("Hfss =%h\n", SHA256_DIGEST_LENGTH, hashes.fuses_hash);

	/* Sense info into RAM array; hash array. */
	for (i = 0; i < INFO_MAX; ++i)
		info[i] = INFO_IGNORE;

	for (i = 0; i < INFO_MAX; ++i) {
		if (hdr->infomap[i>>5] & (1 << (i&31))) {
			uint32_t val = 0;
			/* read 1st bank of info */
			int retval = flash_info_read(i, &val);

			info[i] ^= val ^ retval;
		}
	}

	hwSHA256((uint8_t *) info, sizeof(info), hashes.info_hash);
	debug_printf("Hinf =%h\n", SHA256_DIGEST_LENGTH, hashes.info_hash);

	/* Hash our set of hashes to get final hash. */
	hwSHA256((uint8_t *) &hashes, sizeof(hashes), hash);
	
	/* Verify the hash checksums. */
	if (hdr->img_chk_ != hashes.img_hash[0] ||
		hdr->fuses_chk_ != hashes.fuses_hash[0] ||
		hdr->info_chk_ != hashes.info_hash[0])
		return;

	verify_reg_table(hdr->expect_response_);
	apply_header_security(hdr);


	/*
	 * Write measured hash to unlock register to try and unlock execution.
	 * This would match when doing warm-boot from suspend, so we can avoid
	 * the slow RSA verify.
	 */
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
		GREG32_ADDR(GLOBALSEC, SB_BL_SIG0)[i] = hash[i];

	/*
	 * Unlock attempt. Value written is irrelevant, as long as something
	 * is written.
	 */
	GREG32(GLOBALSEC, SIG_UNLOCK) = 0;

	if (!unlockedForExecution()) {
		/* Assume warm-boot failed; do full RSA verify. */
		LOADERKEY_verify(hdr->keyid, hdr->signature, hash);

		if (unlockedForExecution()) {
			for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
				G32PROT_OFFSET(PMU, PWRDN_SCRATCH0, i, hash[i]);
		}
	}

	if (!unlockedForExecution())
		return;


	verify_reg_table(hdr->expect_response_);
	
	/*
	 * Write PMU_PWRDN_SCRATCH_LOCK_OFFSET to lock against rewrites.
	 */
	G32PROT(PMU, PWRDN_SCRATCH_LOCK, 0);

	/*
	 * Drop software level to RUNLEVEL_HIGH
	 */
    G32PROT(GLOBALSEC, SOFTWARE_LVL, 0x3c);

	/* Write hdr->tag, hdr->keyid to KDF engine RWR[0..7] */
    for (i = 0; i < 6; ++i)
		G32PROT_OFFSET(KEYMGR, HKEY_RWR0, i, hdr->tag[i]);
	G32PROT(KEYMGR, HKEY_RWR7, hdr->keyid);

	/*
	 * Lock RWR
	 */
	G32PROT(KEYMGR, RWR_VLD, 2);
	G32PROT(KEYMGR, RWR_LOCK, 0);

	/* 
	 * Read CONFIG1 
	 */
	config1 = G32PROT_VAL(FUSE, FW_DEFINED_BROM_CONFIG1) | hdr->config1_;

	/*
	 * Flash write protect entire image area (to guard signed blob)
	 */
	G32PROT(GLOBALSEC, FLASH_REGION0_BASE_ADDR, adr);
	G32PROT(GLOBALSEC, FLASH_REGION0_SIZE, hdr->image_size - 1);
	G32PROT(GLOBALSEC, FLASH_REGION0_CTRL, 3);

	/*
	 * Set FLASH and CPU permissions according to config1_ 
	 */
	if (config1 & 2)
		G32PROT(GLOBALSEC, FLASH_REGION0_CTRL_CFG_EN, 0);
	if (config1 & 4)
		G32PROT(GLOBALSEC, FLASH0_BULKERASE_CFG_EN, 0);
	if (config1 & 8)
		G32PROT(GLOBALSEC, FLASH1_BULKERASE_CFG_EN, 0);
	if (config1 & 1) {
		/* Lower the rest of the CPU permissions */
		G32PROT(GLOBALSEC, CPU0_S_DAP_PERMISSION, 0x3c);
		G32PROT(GLOBALSEC, CPU0_S_PERMISSION, 0x3c);
		G32PROT(GLOBALSEC, DDMA0_PERMISSION, 0x3c);
	}

	disarmRAMGuards();

	/* Verify everything is secure one last time before jumping */
	apply_header_security(hdr);

	/* Set the vector base. */
	G32PROT(M3, VTOR, adr + sizeof(struct SignedHeader));
	
	verify_reg_table(hdr->expect_response_);
	verify_reg_counter(7, hdr->expect_response_);

	debug_printf("jump @%8x\n", adr + sizeof(struct SignedHeader));
	_jump_to_address(&hdr[1]);
}
