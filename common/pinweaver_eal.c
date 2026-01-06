/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <common.h>
#include <extension.h>
#include <hooks.h>
#include <new_nvmem.h>
#include <nvmem_vars.h>
#include <pinweaver_eal.h>
#include <pinweaver_eal_types.h>
#include <pinweaver_tpm_imports.h>
#include <timer.h>
#include <tpm_vendor_cmds.h>
#include <trng.h>
#include <tpm_registers.h>
#include <util.h>

/* Make sure the largest possible message would fit in
 * (struct tpm_register_file).data_fifo.
 */
BUILD_ASSERT(PW_MAX_MESSAGE_SIZE + sizeof(struct tpm_cmd_header) <= 2048);

/* Verify that the nvmem_vars log entries have the correct sizes. */
BUILD_ASSERT(sizeof(struct pw_long_term_storage_t) +
	     sizeof(PW_TREE_VAR) - 1 <= MAX_VAR_BODY_SPACE);
BUILD_ASSERT(sizeof(struct pw_log_storage_t) +
	     sizeof(PW_LOG_VAR0) - 1 <= MAX_VAR_BODY_SPACE);
BUILD_ASSERT(sizeof(struct pw_ba_pk_t) +
	     sizeof(PW_FP_PK) - 1 <= MAX_VAR_BODY_SPACE);

int pinweaver_eal_memcpy_s(
    void * dest,
    size_t destsz,
    const void * src,
    size_t count
)
{
	if (count == 0)
		return 0;

	if (dest == NULL)
		return -1;

	if (src == NULL) {
		memset(dest, 0, destsz);
		return -1;
	}

	if (destsz < count) {
		memset(dest, 0, destsz);
		return -1;
	}

    memcpy(dest, src, count);
    return 0;
}

int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree)
{
	int ret = EC_SUCCESS;
	const uint32_t KEY_TYPE_AES = 0x0;
	const uint32_t KEY_TYPE_HMAC = 0xffffffff;
	union {
		uint32_t v[8];
		uint8_t bytes[sizeof(uint32_t) * 8];
	} input;
	uint32_t type_field;
	size_t seed_size = sizeof(input);
	size_t x;

	get_storage_seed(input.v, &seed_size);
	for (x = 0; x < ARRAY_SIZE(input.bytes) &&
		    x < ARRAY_SIZE(merkle_tree->key_derivation_nonce); ++x)
		input.bytes[x] ^= merkle_tree->key_derivation_nonce[x];
	type_field = input.v[6];

	if (!DCRYPTO_appkey_init(PINWEAVER))
		return PW_ERR_CRYPTO_FAILURE;

	input.v[6] = type_field ^ KEY_TYPE_AES;
	if (!DCRYPTO_appkey_derive(PINWEAVER, input.v,
				  (uint32_t *)merkle_tree->wrap_key)) {
		ret = PW_ERR_CRYPTO_FAILURE;
		goto cleanup;
	}

	input.v[6] = type_field ^ KEY_TYPE_HMAC;
	if (!DCRYPTO_appkey_derive(PINWEAVER, input.v,
				  (uint32_t *)merkle_tree->hmac_key)) {
		ret = PW_ERR_CRYPTO_FAILURE;
	}
cleanup:
	DCRYPTO_appkey_finish();
	return ret;
}

int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx)
{
	return DCRYPTO_hw_sha256_init(ctx) != DCRYPTO_OK;
}

int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
				const void *data,
				size_t size)
{
	HASH_update((union hash_ctx *)ctx, data, size);
	return 0;
}

int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx,
			       void *res)
{
	memcpy(res, HASH_final((union hash_ctx *)ctx), SHA256_DIGEST_SIZE);
	return 0;
}

int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				   const void *key,
				   size_t key_size /* in bytes */)
{
	if (key_size != 256/8)
		return -1;
	return DCRYPTO_hw_hmac_sha256_init(ctx, key, key_size) != DCRYPTO_OK;
}
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				     const void *data,
				     size_t size)
{
	HMAC_SHA256_update(ctx, data, size);
	return 0;
}

int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				    void *res)
{
	memcpy(res, HMAC_SHA256_final(ctx), SHA256_DIGEST_SIZE);
	return 0;
}

int pinweaver_eal_aes256_ctr(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res)
{
	return DCRYPTO_aes_ctr(res, key, key_size << 3, iv, data, size) != DCRYPTO_OK;
}

int pinweaver_eal_aes256_ctr_custom(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res)
{
	return pinweaver_eal_aes256_ctr(key, key_size, iv, data, size, res);
}

int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len)
{
	return safe_memcmp(s1, s2, len);
}

int pinweaver_eal_rand_bytes(void *buf, size_t size)
{
	return !fips_rand_bytes(buf, size);
}

uint64_t pinweaver_eal_seconds_since_boot()
{
	return get_seconds_since_cold_boot();
}

int pinweaver_eal_storage_start()
{
	return 0;
}

static int pinweaver_eal_storage_get_log_var(const struct tuple **var_ptr,
					     struct pw_log_storage_t **log_ptr)
{
	struct pw_log_storage_t *log;
	const struct tuple *ptr;

	*var_ptr = NULL;
	*log_ptr = NULL;

	ptr = getvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1);
	if (!ptr)
		return PW_ERR_NV_EMPTY;

	log = (void *)tuple_val(ptr);
	/* Add storage format updates here. */
	if (ptr->val_len != sizeof(struct pw_log_storage_t)) {
		freevar(ptr);
		return PW_ERR_NV_LENGTH_MISMATCH;
	}
	if (log->storage_version != PW_STORAGE_VERSION) {
		freevar(ptr);
		return PW_ERR_NV_VERSION_MISMATCH;
	}

	*var_ptr = ptr;
	*log_ptr = log;
	return EC_SUCCESS;
}

int pinweaver_eal_storage_init_state(uint8_t root_hash[PW_HASH_SIZE],
				     uint32_t *restart_count)
{
	const struct tuple *var;
	struct pw_log_storage_t *log;
	int ret;

	ret = pinweaver_eal_storage_get_log_var(&var, &log);
	if (ret != EC_SUCCESS)
		return ret;

	memcpy(root_hash, log->entries[0].root, PW_HASH_SIZE);

	/* This forces an NVRAM write for hard reboots for which the
	 * timer value gets reset. The TPM restart and reset counters
	 * were not used because they do not track the state of the
	 * counter.
	 *
	 * Pinweaver uses the restart_count to know when the time since
	 * boot can be used as the elapsed time for the delay schedule,
	 * versus when the elapsed time starts from a timestamp.
	 */
	if (pinweaver_eal_seconds_since_boot() < RESTART_TIMER_THRESHOLD) {
		++log->restart_count;
		ret = setvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1,
			     (uint8_t *)log, sizeof(struct pw_log_storage_t));
		if (ret != EC_SUCCESS) {
			freevar(var);
			return ret;
		}
	}
	*restart_count = log->restart_count;
	freevar(var);
	return EC_SUCCESS;
}

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest)
{
	const struct tuple *var;
	struct pw_log_storage_t *log;

	int rv = pinweaver_eal_storage_get_log_var(&var, &log);
	if (rv != EC_SUCCESS)
		return rv;

	memcpy(dest, log, sizeof(struct pw_log_storage_t));

	freevar(var);

	return EC_SUCCESS;
}

int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log)
{
	return setvar(PW_LOG_VAR0, sizeof(PW_LOG_VAR0) - 1, (uint8_t *)log,
		      sizeof(struct pw_log_storage_t));
}


int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest)
{
	const struct pw_long_term_storage_t *tree;
	const struct tuple *ptr;

	ptr = getvar(PW_TREE_VAR, sizeof(PW_TREE_VAR) - 1);
	if (!ptr)
		return PW_ERR_NV_EMPTY;

	tree = (void *)tuple_val(ptr);
	/* Add storage format updates here. */
	if (ptr->val_len != sizeof(*tree)) {
		freevar(ptr);
		return PW_ERR_NV_LENGTH_MISMATCH;
	}
	if (tree->storage_version != PW_STORAGE_VERSION) {
		freevar(ptr);
		return PW_ERR_NV_VERSION_MISMATCH;
	}

	memcpy(dest, tree, sizeof(struct pw_long_term_storage_t));
	freevar(ptr);
	return EC_SUCCESS;
}

int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data)
{
	return setvar(PW_TREE_VAR, sizeof(PW_TREE_VAR) - 1,
		      (uint8_t *)data, sizeof(struct pw_long_term_storage_t));
}

uint8_t pinweaver_eal_get_current_pcr_digest(
		const uint8_t bitmask[2],
		uint8_t sha256_of_selected_pcr[32])
{
	return get_current_pcr_digest(bitmask, sha256_of_selected_pcr);
}

static int pinweaver_eal_storage_get_ba_pk_var(uint8_t auth_channel,
							 const struct tuple **var_ptr,
					     struct pw_ba_pk_t **pk_ptr)
{
	struct pw_ba_pk_t *pk;
	const struct tuple *ptr;

	*var_ptr = NULL;
	*pk_ptr = NULL;

	if (auth_channel != PW_FP_AUTH_CHANNEL) {
		return PW_ERR_INTERNAL_FAILURE;
	}

	ptr = getvar(PW_FP_PK, sizeof(PW_FP_PK) - 1);
	if (!ptr)
		return PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED;

	pk = (void *)tuple_val(ptr);
	if (ptr->val_len != sizeof(struct pw_ba_pk_t)) {
		freevar(ptr);
		return PW_ERR_NV_LENGTH_MISMATCH;
	}

	*var_ptr = ptr;
	*pk_ptr = pk;
	return EC_SUCCESS;
}

int pinweaver_eal_storage_get_ba_pk(uint8_t auth_channel,
				     struct pw_ba_pk_t *dest)
{
	const struct tuple *var;
	struct pw_ba_pk_t *pk;

	int rv = pinweaver_eal_storage_get_ba_pk_var(auth_channel, &var, &pk);
	if (rv != EC_SUCCESS)
		return rv;

	memcpy(dest, pk, sizeof(struct pw_ba_pk_t));

	freevar(var);

	return EC_SUCCESS;
}

int pinweaver_eal_storage_set_ba_pk(uint8_t auth_channel,
				     const struct pw_ba_pk_t *pk)
{
	if (auth_channel != PW_FP_AUTH_CHANNEL) {
		return -1;
	}
	return setvar(PW_FP_PK, sizeof(PW_FP_PK) - 1, (uint8_t *)pk,
		      sizeof(struct pw_ba_pk_t));
}



int pinweaver_eal_ecdh_derive(const struct pw_ba_ecc_pt_t *ecc_pt_in,
				     void *secret, size_t *secret_size,
				     struct pw_ba_ecc_pt_t *ecc_pt_out)
{
	p256_int self_pk_x, self_pk_y, d;
	p256_int peer_pk_x, peer_pk_y;
	p256_int shared_pt_x, unused_shared_pt_y;
	uint8_t key_seed[P256_NBYTES];
	int result;

	if (*secret_size < P256_NBYTES) {
		return PW_ERR_INTERNAL_FAILURE;
	}

	p256_from_bin(ecc_pt_in->x, &peer_pk_x);
	p256_from_bin(ecc_pt_in->y, &peer_pk_y);
	if (DCRYPTO_p256_is_valid_point(&peer_pk_x, &peer_pk_y) != DCRYPTO_OK) {
		return PW_ERR_CRYPTO_FAILURE;
	}

	/* Generate a random key pair for ECDH. */
	do {
		if (!fips_rand_bytes(key_seed, P256_NBYTES)) {
			return PW_ERR_CRYPTO_FAILURE;
		}
		result = DCRYPTO_p256_key_from_bytes(&self_pk_x, &self_pk_y, &d, key_seed);
	} while (result == DCRYPTO_RETRY);
	if (result != DCRYPTO_OK) {
		return PW_ERR_CRYPTO_FAILURE;
	}

	/* Perform ECDH. x-coordinate of the shared point is used as the secret. */
	if (DCRYPTO_p256_point_mul(
				&shared_pt_x,
				&unused_shared_pt_y,
				&d,
				&peer_pk_x,
				&peer_pk_y
		) != DCRYPTO_OK) {
		return PW_ERR_CRYPTO_FAILURE;
	}

	*secret_size = P256_NBYTES;
	p256_to_bin(&shared_pt_x, secret);
	p256_to_bin(&self_pk_x, ecc_pt_out->x);
	p256_to_bin(&self_pk_y, ecc_pt_out->y);

	return EC_SUCCESS;
}

/*
 * Handle the VENDOR_CC_PINWEAVER command.
 */
static enum vendor_cmd_rc pw_vendor_specific_command(enum vendor_cmd_cc code,
						     void *buf,
						     size_t input_size,
						     size_t *response_size)
{
	switch (pinweaver_command(buf, input_size, buf, response_size)) {
		case PW_CMD_RES_SUCCESS:
			return VENDOR_RC_SUCCESS;
		case PW_CMD_RES_SIZE:
			return VENDOR_RC_REQUEST_TOO_BIG;
		default:
			return VENDOR_RC_INTERNAL_ERROR;
	}
}
DECLARE_VENDOR_COMMAND(VENDOR_CC_PINWEAVER, pw_vendor_specific_command);
