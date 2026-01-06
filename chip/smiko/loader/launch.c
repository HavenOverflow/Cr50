/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "dcrypto.h"
#include "debug_printf.h"
#include "registers.h"
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

	__builtin_unreachable();
}

void tryLaunch(uint32_t adr, size_t max_size, uint32_t *ladder)
{
	static struct header_hashes hashes;
	static uint32_t ladderbuf[SHA256_DIGEST_WORDS];
	static uint32_t hash[SHA256_DIGEST_WORDS];
	static uint32_t fuses[FUSE_MAX];
	static uint32_t info[INFO_MAX];
	int i;
	uint32_t major, dev, config1;
    const struct SignedHeader *hdr = (const struct SignedHeader *)(adr);
	struct SignedHeader *ro_hdr = (struct SignedHeader *)(CONFIG_PROGRAM_MEMORY_BASE + 
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

	/* Validity check that image has a valid key ID. This should prevent any images with different
	 * signatures from running.
	 */
	if (!is_good_key(&hdr->keyid))
        return;

	/* We're about to launch an image with a matching key ID. Give any connected
	 * hosts the option to manually run cr50-rescue instead of requiring an invalid RW.
	 */
    attempt_sync(2);

	
	/* TODO: harden against glitching: multi readback, check? */
	GREG32(GLOBALSEC, CPU0_I_STAGING_REGION1_BASE_ADDR) = hdr->rx_base;
	GREG32(GLOBALSEC, CPU0_I_STAGING_REGION1_SIZE) =
		hdr->rx_max - hdr->rx_base - 1;
	GWRITE_FIELD(GLOBALSEC, CPU0_I_STAGING_REGION1_CTRL, EN, 1);
	GWRITE_FIELD(GLOBALSEC, CPU0_I_STAGING_REGION1_CTRL, RD_EN, 1);

	DCRYPTO_SHA256_hash((uint8_t *) &hdr->tag,
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

	dev = is_dev_loader(hdr->keyid);

	/* If the RO is dev-signed or config1_ suggests the image is node-locked,
	 * then read the DEV IDs into the end of the fuse map to be hashed.
	 */
    if (dev || hdr->config1_ < 0) {
        fuses[FUSE_MAX - 2] = GREG32(FUSE, DEV_ID0);
        fuses[FUSE_MAX - 1] = GREG32(FUSE, DEV_ID1);
    }

	DCRYPTO_SHA256_hash((uint8_t *) fuses, sizeof(fuses),
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

	DCRYPTO_SHA256_hash((uint8_t *) info, sizeof(info),
			(uint8_t *) hashes.info_hash);

	/* Check if any connected hosts requested a rescue, and engage accordingly. */
	if (check_engage_rescue(2, &hashes) != 0x1a5a3cc3)
        system_reset(0xffffffff);
	// according to the decomp, its Himg={first_img_hash_word}..{last_img_hash_word}: {hdr->img_chk_ == first_img_hash_word}
	// infact, it is CLEARLY stated in SignedHeader that img_chk_ is the top 32 bits of the expected img hash...
    debug_printf("Himg =%X..%X: %d\n", hashes.img_hash[0], 
		hashes.img_hash[SHA256_DIGEST_WORDS],
		hdr->img_chk_ == hashes.img_hash[0]);
    debug_printf("Hfss =%X..%X: %d\n", hashes.fuses_hash[0], 
		hashes.fuses_hash[SHA256_DIGEST_WORDS], 
		hdr->fuses_chk_ == hashes.fuses_hash[0]);
    debug_printf("Hinf =%X..%X: %d\n", hashes.info_hash[0], 
		hashes.info_hash[SHA256_DIGEST_WORDS], 
		hdr->info_chk_ == hashes.info_hash[0]);

	/* Hash our set of hashes to get final hash. */
	DCRYPTO_SHA256_hash((uint8_t *) &hashes, sizeof(hashes),
			(uint8_t *) hash);

	/* XOR the hash with our randomized ladder. */
	for (i = 0; i < SHA256_DIGEST_WORDS; i++)
		ladderbuf[i] = hash[i] ^ ladder[i];

	/*
	 * Write measured hash to unlock register to try and unlock execution.
	 * This would match when doing warm-boot from suspend, so we can avoid
	 * the slow RSA verify.
	 */
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
		GREG32_ADDR(GLOBALSEC, SB_BL_SIG0)[i] = ladderbuf[i];

	/*
	 * Unlock attempt. Value written is irrelevant, as long as something
	 * is written.
	 */
	GREG32(GLOBALSEC, SIG_UNLOCK) = 1;

	if (!unlockedForExecution()) {
        /* Assume warm-boot failed; do full RSA verify. */
        LOADERKEY_verify(&hdr->keyid, hdr->signature, hash);
        /*
		 * PWRDN_SCRATCH* should be write-locked, tied to successful
		 * SIG_MATCH. Thus ARM is only able to write this hash if
		 * signature was correct.
		 */
        for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
			/* TODO: verify written values as glitch protection? */
			GREG32_ADDR(PMU, PWRDN_SCRATCH8)[i] = hash[i];
    }

	if (!unlockedForExecution())
        return;

	/*
	 * Write PMU_PWRDN_SCRATCH_LOCK1_OFFSET to lock against rewrites.
	 * TODO: glitch resist
	 */
	GREG32(PMU, PWRDN_SCRATCH_LOCK1) = 1;

	/*
	 * Drop software level to stop SIG_MATCH from future write-unlocks.
	 * TODO: glitch detect / verify?
	 */
    GREG32(GLOBALSEC, SOFTWARE_LVL) = 0x33;

    /* Write hdr->tag, hdr->epoch_ to KDF engine FWR[0..7] */
    for (i = 0; i < ARRAY_SIZE(hdr->tag); ++i)
		GREG32_ADDR(KEYMGR, HKEY_FWR0)[i] = hdr->tag[i];

    GREG32(KEYMGR, HKEY_FWR7) = is_dev_loader(hdr->keyid) | dev;

	/* Let's warn any connected hosts if the image we're jumping to is dev signed. */
	debug_printf("devm :%u\n", is_dev_loader(hdr->keyid) | dev);
    if (is_prod_signed(hdr->keyid) || hdr->infomap[0] >= 0) 
		resetProtections(0xffffffff);

	major = hdr->major_;
	GREG32(KEYMGR, FW_MAJOR_VERSION) = major;

	/*
	 * Lock FWR (NOTE: needs to happen after writing major!) TODO: glitch
	 * protect?
	 */
	GREG32(KEYMGR, FWR_VLD) = 2;
	GREG32(KEYMGR, FWR_LOCK) = 1;

	/* TODO: bump runlevel(s) according to signature header */
	/*
	 * Flash write protect entire image area (to guard signed blob)
	 * REGION0 protects boot_loader, use REGION1 to protect app
	 */
	GREG32(GLOBALSEC, FLASH_REGION1_BASE_ADDR) = adr;
	GREG32(GLOBALSEC, FLASH_REGION1_SIZE) = hdr->image_size - 1;
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, EN, 1);
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, RD_EN, 1);
	GWRITE_FIELD(GLOBALSEC, FLASH_REGION1_CTRL, WR_EN, 0);

	config1 = ro_hdr->config1_;
    sync_expr(hdr->err_response_ | config1);

	/* TODO: lock FLASH_REGION 1? */
	disarmRAMGuards();
	sync_expr(hdr->err_response_ | config1);
    verify_err_resp(0xd, hdr->err_response_ | config1);

	debug_printf("jump @%x\n", adr);

	_jump_to_address(&hdr[1]);
}
