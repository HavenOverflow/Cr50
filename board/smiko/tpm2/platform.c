/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "Global.h"
#include "Platform.h"
#include "TPM_Types.h"

#include "boot_param_platform_cr50.h"
#include "ccd_config.h"
#include "console.h"
#include "nvmem_vars.h"
#include "pinweaver.h"
#include "pinweaver_eal.h"
#include "tpm_nvmem.h"
#include "tpm_nvmem_ops.h"
#include "dcrypto.h"
#include "u2f_impl.h"
#include "util.h"
#include "version.h"

#define CPRINTF(format, args...) cprintf(CC_EXTENSION, format, ## args)

uint16_t _cpri__GenerateRandom(int32_t random_size,
			uint8_t *buffer)
{
	if (!fips_rand_bytes(buffer, random_size))
		return 0;
	return random_size;
}

/*
 * Return the pointer to the character immediately after the first dash
 * encountered in the passed in string, or NULL if there is no dashes in the
 * string.
 */
static const char *char_after_dash(const char *str)
{
	char c;

	do {
		c = *str++;

		if (c == '-')
			return str;
	} while (c);

	return NULL;
}

/*
 * The properly formatted build_info string has the ec code SHA1 after the
 * first dash, and tpm2 code sha1 after the second dash.
 */

void   _plat__GetFwVersion(uint32_t *firmwareV1, uint32_t *firmwareV2)
{
	const char *ver_str = char_after_dash(build_info);

	/* Just in case the build_info string is misformatted. */
	*firmwareV1 = 0;
	*firmwareV2 = 0;

	if (!ver_str)
		return;

	*firmwareV1 = strtoi(ver_str, NULL, 16);

	ver_str = char_after_dash(ver_str);
	if (!ver_str)
		return;

	*firmwareV2 = strtoi(ver_str, NULL, 16);
}

void _plat__StartupCallback(void)
{
	pinweaver_init();
	boot_param_handle_tpm_startup();

	/*
	 * Eventually, we'll want to allow CCD unlock with no password, so
	 * enterprise policy can set a password to block CCD instead of locking
	 * it out via the FWMP.
	 *
	 * When we do that, we'll allow unlock without password between a real
	 * TPM startup (not just a resume) - which is this callback - and
	 * explicit disabling of that feature via a to-be-created vendor
	 * command.  That vendor command will be called after enterprize policy
	 * is updated, or the device is determined not to be enrolled.
	 *
	 * But for now, we'll just block unlock entirely if no password is set,
	 * so we don't yet need to tell CCD that a real TPM startup has
	 * occurred.
	 */

	/* TODO(b/262324344). Remove when zero sized EPS fixed. */
	if (gp.EPSeed.t.size != PRIMARY_SEED_SIZE ||
	    gp.SPSeed.t.size != PRIMARY_SEED_SIZE) {
		CPRINTF("%s: Seed length is zero [%x, %x]!\n", __func__,
			gp.EPSeed.t.size, gp.SPSeed.t.size);
		cflush();
	}
}

BOOL _plat__ShallSurviveOwnerClear(uint32_t  index)
{
	return index == HR_NV_INDEX + NV_INDEX_FWMP;
}

static void cleanup_report(const char *func, const char *id,
			   enum ec_error_list status)
{
	if (status != EC_SUCCESS)
		CPRINTF("%s: %s cleanup failed (%d)\n", func, id, status);
}

void _plat__OwnerClearCallback(void)
{
	/* Invalidate existing biometrics pairing secrets. */
	cleanup_report(__func__, "pw pk",
		       setvar(PW_FP_PK, sizeof(PW_FP_PK) - 1, NULL, 0));
	cleanup_report(__func__, "pw tree",
		       setvar(PW_TREE_VAR, sizeof(PW_TREE_VAR) - 1, NULL, 0));
	cleanup_report(__func__, "pw log",
		       setvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1, NULL, 0));

	/* Invalidate existing u2f registrations. */
	cleanup_report(__func__, "u2f", u2f_zeroize_keys());

	boot_param_handle_owner_clear();
}

/* Prints the contents of pcr0 */
void print_pcr0(void)
{
	uint8_t pcr0_value[SHA256_DIGEST_SIZE];

	ccprintf("pcr0:    ");
	if (!get_tpm_pcr_value(0, pcr0_value)) {
		ccprintf("error\n");
		return;
	}
	ccprintf("%ph\n", HEX_BUF(&pcr0_value, SHA256_DIGEST_SIZE));
}

BOOL _plat__NvUpdateAllowed(uint32_t handle)
{
	return TRUE;
}
