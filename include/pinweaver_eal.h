
/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_H
#define __PINWEAVER_EAL_H

#include <stddef.h>

#include "pinweaver.h"
#include "pinweaver_eal_types.h"

#ifndef PINWEAVER_EAL_INFO
#define PINWEAVER_EAL_INFO(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Implements memcpy_s on all platforms
 */
int pinweaver_eal_memcpy_s(
    void * dest,
    size_t destsz,
    const void * src,
    size_t count
);

/*
 * Derives wrap_key and hmac_key based on key_derivation_nonce.
 * Returns 0 on success.
 */
int pinweaver_eal_derive_keys(struct merkle_tree_t *merkle_tree);

/*
 * Functions for calculating SHA-256.
 * Returns 0 on success.
 */
int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t *ctx);
int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t *ctx,
				const void *data,
				size_t size);
int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t *ctx,
			       void *res);

/*
 * Functions for calculating HMAC SHA-256.
 * Only 256 bit key size is used.
 * Returns 0 on success.
 */
int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				   const void *key,
				   size_t key_size /* in bytes */);
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				     const void *data,
				     size_t size);
int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t *ctx,
				    void *res);

/*
 * Perform AES-256 CTR.
 * Only 256 bit key size is used.
 * Returns 0 on success.
 */
int pinweaver_eal_aes256_ctr(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res);

/*
 * Perform AES-256 CTR, with a custom key.
 * Only 256 bit key size is used.
 * Returns 0 on success.
 *
 * b/267729980: To keep keys hardware-bound, Ti50 adopted a workaround
 * to not actually export/import the keys as expected by PinWeaver. Instead,
 * it stores the wrapping key/hmac key itself during key derivation and
 * always use the wrapping key for AES, hmac key for HMAC. This works fine
 * until we start to use AES in PinWeaver with a custom key instead of the
 * wrapping key. We don't want to alter the existing design of Ti50 eals so
 * instead introduced a new eal. On other platforms, this eal is equivalent
 * to pinweaver_eal_aes256_ctr. On Ti50, this eal needs to properly import the
 * given key and use it for encryption.
 */
int pinweaver_eal_aes256_ctr_custom(const void *key,
			     size_t key_size, /* in bytes */
			     const void *iv,
			     const void *data,
			     size_t size,
			     void *res);


/*
 * Constant time implementation of memcmp to avoid timing side channels.
 */
int pinweaver_eal_safe_memcmp(const void *s1, const void *s2, size_t len);

/*
 * Get random bytes.
 * Returns 0 on success.
 */
int pinweaver_eal_rand_bytes(void *buf, size_t size);

/*
 * Get number of seconds since cold boot.
 */
uint64_t pinweaver_eal_seconds_since_boot(void);

/*
 * Functions for calculating SHA256 of the values of the selected PCRs.
 * Returns 0 on success.
 */
uint8_t pinweaver_eal_get_current_pcr_digest(
		const uint8_t bitmask[2],
		uint8_t sha256_of_selected_pcr[32]);

/*
 * Storage functions.
 * Return 0 on success.
 */
int pinweaver_eal_storage_start(void);
int pinweaver_eal_storage_init_state(uint8_t root_hash[PW_HASH_SIZE],
				     uint32_t *restart_count);

int pinweaver_eal_storage_get_log(struct pw_log_storage_t *dest);
int pinweaver_eal_storage_set_log(const struct pw_log_storage_t *log);

int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t *dest);
int pinweaver_eal_storage_set_tree_data(
		const struct pw_long_term_storage_t *data);

/* Biometrics vendor functions. */

/*
 * Load the Pk of the specified auth channel.
 * The pk should be valid when status is return code is 0.
 * Returns 0 on success.
 * Returns PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED when the Pk is not established.
 */
int pinweaver_eal_storage_get_ba_pk(uint8_t auth_channel,
				     struct pw_ba_pk_t *pk);

/*
 * Set the Pk of the specified auth channel.
 * Returns 0 on success.
 */
int pinweaver_eal_storage_set_ba_pk(uint8_t auth_channel,
				     const struct pw_ba_pk_t *pk);

/*
 * Derive a ECC key pair, perform ECDH exchange with the |ecc_pt_in| public
 * point, set |secret| as the shared secret, and set |ecc_pt_out| as the
 * derived ECC key pair's public point.
 */
int pinweaver_eal_ecdh_derive(const struct pw_ba_ecc_pt_t *ecc_pt_in,
				     void *secret, size_t *secret_size,
				     struct pw_ba_ecc_pt_t *ecc_pt_out);

#ifdef __cplusplus
}
#endif

#endif  /* __PINWEAVER_EAL_H */
