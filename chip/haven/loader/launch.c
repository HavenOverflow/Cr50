/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "dcrypto.h"
#include "debug_printf.h"
#include "registers.h"
#include "regtable.h"
#include "rescue.h"
#include "rom_flash.h"
#include "setup.h"
#include "signed_header.h"
#include "system.h"
#include "uart.h"
#include "verify.h"

static int unlockedForExecution(void)
{
	return GREAD_FIELD(GLOBALSEC, SB_COMP_STATUS, SB_BL_SIG_MATCH);
}

void _jump_to_address(const void *addr)
{
	REG32(GC_M3_VTOR_ADDR) = (unsigned)addr;  /* Set vector base. */

	__asm__ volatile("ldr sp, [%0]; \
			ldr pc, [%0, #4];"
			 : : "r"(addr)
			 : "memory");
}

static struct {
	uint32_t img_hash[SHA256_DIGEST_WORDS];
	uint32_t fuses_hash[SHA256_DIGEST_WORDS];
	uint32_t info_hash[SHA256_DIGEST_WORDS];
} hashes;
uint32_t hash[SHA256_DIGEST_WORDS];

void tryLaunch(uint32_t adr, size_t max_size, uint32_t *ladder)
{
	static uint32_t encoded_hash[SHA256_DIGEST_WORDS];
	static uint32_t fuses[FUSE_MAX];
	static uint32_t info[INFO_MAX];
	int i;
	uint32_t major, dev, config1;
    const struct SignedHeader *hdr = (const struct SignedHeader *)(adr);
	struct SignedHeader *me = (struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE + 
	             CONFIG_RO_MEM_OFF);

	memset(hash, 0, sizeof(hash));

	/* Validity check image header. */
	if (hdr->magic != -1)
		return;
	if (hdr->image_size > max_size)
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

	/* Validity checks that image uses known key. */
	if (!LOADERKEY_find(&hdr->keyid))
		return;

	rescue_sync(2);
	
	/* Setup candidate execution region 1 based on header information. */
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION1_BASE_ADDR, hdr->rx_base);
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION1_SIZE,
		hdr->rx_max - hdr->rx_base - 1);
	G32PROT(GLOBALSEC, CPU0_I_STAGING_REGION1_CTRL, 3);

	HwSHA256((uint8_t *) &hdr->tag,
			hdr->image_size - offsetof(struct SignedHeader, tag),
			(uint8_t *) hashes.img_hash);

	/* Sense fuses into RAM array; hash array. */
	/* TODO: is this glitch resistant enough? Certainly is simple.. */
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

	/* If the image is signed with a node-locked key, read the dev id's
	 * into our fuses before hashing. These are unique to each chip, and thus should
	 * prevent a dev image from running on any H1.
	 */
    if (is_node_locked_key(hdr->keyid) || hdr->config1_ < 0) {
        fuses[5] = GREG32(FUSE, DEV_ID0);
        fuses[6] = GREG32(FUSE, DEV_ID1);
    }

	HwSHA256((uint8_t *) fuses, sizeof(fuses),
			(uint8_t *) hashes.fuses_hash);


	/* Sense info into RAM array; hash array. */
	for (i = 0; i < INFO_MAX; ++i)
		info[i] = INFO_IGNORE;

	for (i = 0; i < INFO_MAX; ++i) {
		if (hdr->infomap[i>>5] & (1 << (i&31))) {
			uint32_t val = 0;
			/* read 2nd bank of info */
			int retval = flash_info_read(i + INFO_MAX, &val);

			info[i] ^= val ^ retval;
		}
	}

	HwSHA256((uint8_t *) info, sizeof(info),
			(uint8_t *) hashes.info_hash);

	/* Engage rescue mode if requested and allowed. */
	if (check_engage_rescue(2, &hashes) != 0x1a5a3cc3)
        system_reset(-1);
	
    debug_printf("Himg =%X..%X: %d\n", hashes.img_hash[0], 
		hashes.img_hash[SHA256_DIGEST_WORDS - 1],
		hdr->img_chk_ == hashes.img_hash[0]);
    debug_printf("Hfss =%X..%X: %d\n", hashes.fuses_hash[0], 
		hashes.fuses_hash[SHA256_DIGEST_WORDS - 1], 
		hdr->fuses_chk_ == hashes.fuses_hash[0]);
    debug_printf("Hinf =%X..%X: %d\n", hashes.info_hash[0], 
		hashes.info_hash[SHA256_DIGEST_WORDS - 1], 
		hdr->info_chk_ == hashes.info_hash[0]);

	/* Hash our set of hashes to get final hash. */
	HwSHA256((uint8_t *) &hashes, sizeof(hashes),
			(uint8_t *) hash);

	/* XOR the hash with our ladder. This should prevent voltage glitching
	 * from exploiting warmboot to have correct values. 
	 */
	for (i = 0; i < SHA256_DIGEST_WORDS; i++)
		encoded_hash[i] = hash[i] ^ ladder[i];

	/*
	 * Write measured hash to unlock register to try and unlock execution.
	 * This would match when doing warm-boot from suspend, so we can avoid
	 * the slow RSA verify.
	 */
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
		GREG32_ADDR(GLOBALSEC, SB_BL_SIG0)[i] = encoded_hash[i];

	/*
	 * Unlock attempt. Value written is irrelevant, as long as something
	 * is written.
	 */
	GREG32(GLOBALSEC, SIG_UNLOCK) = 0;

	if (!unlockedForExecution()) {
        /* Assume warm-boot failed; do full RSA verify. */
        LOADERKEY_verify(&hdr->keyid, hdr->signature, hash);
        
		if (!unlockedForExecution()) {
			for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
				/* TODO: verify written values as glitch protection? */
				G32PROT_OFFSET(PMU, PWRDN_SCRATCH8, i, hash[i]);
		}
    }

	if (!unlockedForExecution())
        return;

	/*
	 * Write PMU_PWRDN_SCRATCH_LOCK1_OFFSET to lock against rewrites.
	 */
	G32PROT(PMU, PWRDN_SCRATCH_LOCK1, 0);

	/*
	 * Drop software level to stop SIG_MATCH from future write-unlocks.
	 */
    G32PROT(GLOBALSEC, SOFTWARE_LVL, 0x33);

    /* Write hdr->tag, hdr->keyid to KDF engine FWR[0..7] */
    for (i = 0; i < 6; ++i)
		G32PROT_OFFSET(KEYMGR, HKEY_FWR0, i, hdr->tag[i]);
    G32PROT(KEYMGR, HKEY_FWR7, is_node_locked_key(hdr->keyid));

	/* Check if the image is using a dev key. */
	debug_printf("devm :%u\n", is_node_locked_key(hdr->keyid));
    if (is_prod_signed(hdr->keyid) || hdr->config1_ >= 0) 
		resetProtections(-1);

	major = hdr->major_;
	G32PROT(KEYMGR, FW_MAJOR_VERSION, major);

	/*
	 * Lock FWR (NOTE: needs to happen after writing major!)
	 */
	G32PROT(KEYMGR, FWR_VLD, 2);
	G32PROT(KEYMGR, FWR_LOCK, 0);

	/*
	 * Flash write protect entire image area (to guard signed blob)
	 * REGION0 protects boot_loader, use REGION1 to protect app
	 */
	G32PROT(GLOBALSEC, FLASH_REGION1_BASE_ADDR, adr);
	G32PROT(GLOBALSEC, FLASH_REGION1_SIZE, hdr->image_size - 1);
	G32PROT(GLOBALSEC, FLASH_REGION1_CTRL, 3);

	config1 = me->config1_;
    verify_reg_table(hdr->err_response_ | config1);

	disarmRAMGuards();

	/* Verify registers once more before jumping. */
	verify_reg_table(hdr->err_response_ | config1);
    verify_reg_counter(13, hdr->err_response_ | config1);

	debug_printf("jump @%x\n", adr);

	_jump_to_address(&hdr[1]);
}
