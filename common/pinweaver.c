/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>
#include <string.h>

#include "pinweaver.h"
#include "pinweaver_eal.h"

/* TODO(apronin): get rid of temporary #defines */

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (256/8)
#endif

#ifndef AES256_BLOCK_CIPHER_KEY_SIZE
#define AES256_BLOCK_CIPHER_KEY_SIZE (256/8)
#endif

#ifndef EC_SUCCESS
#define EC_SUCCESS 0
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef BUILD_ASSERT
/* Test an important condition at compile time, not run time */
#define _BA1_(cond, file, line, msg) \
	_Static_assert(cond, file ":" #line ": " msg)
#define _BA0_(c, f, l, msg) _BA1_(c, f, l, msg)
/* Pass in an option message to display after condition */
#define BUILD_ASSERT(cond, ...) _BA0_(cond, __FILE__, __LINE__, __VA_ARGS__)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* Compile time sanity checks. */
/* Make sure the hash size is consistent with dcrypto. */
BUILD_ASSERT(PW_HASH_SIZE >= SHA256_DIGEST_SIZE);

/* sizeof(struct leaf_data_t) % 16 should be zero */
BUILD_ASSERT(sizeof(struct leaf_sensitive_data_t) % PW_WRAP_BLOCK_SIZE == 0);

BUILD_ASSERT(sizeof(((struct merkle_tree_t *)0)->wrap_key) ==
	     AES256_BLOCK_CIPHER_KEY_SIZE);

/* Verify that the request structs will fit into the message. */
BUILD_ASSERT(PW_MAX_MESSAGE_SIZE >=
	     sizeof(struct pw_request_header_t) +
	     sizeof(union {pw_request_insert_leaf_t insert_leaf;
		     pw_request_remove_leaf_t remove_leaf;
		     pw_request_try_auth_t try_auth;
		     pw_request_reset_auth_t reset_auth;
		     pw_request_get_log_t get_log;
		     pw_request_log_replay_t log_replay; }) +
	     sizeof(struct leaf_public_data_t) +
	     sizeof(struct leaf_sensitive_data_t) +
	     PW_MAX_PATH_SIZE);

#define PW_MAX_RESPONSE_SIZE (sizeof(struct pw_response_header_t) + \
		sizeof(union {pw_response_insert_leaf_t insert_leaf; \
			pw_response_try_auth_t try_auth; \
			pw_response_reset_auth_t reset_auth; \
			pw_response_log_replay_t log_replay; }) + \
		PW_LEAF_PAYLOAD_SIZE)
#define PW_VALID_PCR_CRITERIA_SIZE \
		(sizeof(struct valid_pcr_value_t) * PW_MAX_PCR_CRITERIA_COUNT)
#define PW_EXPIRATION_DATA_SIZE (sizeof(struct pw_timestamp_t) + 4)
/* Verify that the request structs will fit into the message. */
BUILD_ASSERT(PW_MAX_MESSAGE_SIZE >= PW_MAX_RESPONSE_SIZE);

/* PW_MAX_PATH_SIZE should not change unless PW_LEAF_MAJOR_VERSION changes too.
 * Update these statements whenever these constants are changed to remind future
 * maintainers about this requirement.
 *
 * This requirement helps guarantee that forward compatibility across the same
 * PW_LEAF_MAJOR_VERSION doesn't break because of a path length becoming too
 * long after new fields are added to struct wrapped_leaf_data_t or its sub
 * fields.
 */
BUILD_ASSERT(PW_LEAF_MAJOR_VERSION == 0);
BUILD_ASSERT(PW_MAX_PATH_SIZE == 1024);

/* If fields are appended to struct leaf_sensitive_data_t, an encryption
 * operation should be performed on them reusing the same IV since the prefix
 * won't change.
 *
 * If any data in the original struct leaf_sensitive_data_t changes, a new IV
 * should be generated and stored as part of the log for a replay to be
 * possible.
 */
BUILD_ASSERT(sizeof(struct leaf_sensitive_data_t) == 3 * PW_SECRET_SIZE);

/* This var caches the restart count so the nvram log structure doesn't need to
 * be walked every time try_auth request is made.
 */
uint32_t pw_restart_count;

/* If non-zero, Pk establishment is blocked. The client should send a
 * block_generate_ba_pk command after the client platform passed the stage
 * that Pk establishment is allowed. This reduces the risk of active attackers
 * trying to establish Pk with the server.
 */
int generate_ba_pk_blocked;

/******************************************************************************/
/* Struct helper functions.
 */

void import_leaf(const struct unimported_leaf_data_t *unimported,
		 struct imported_leaf_data_t *imported)
{
	imported->head = &unimported->head;
	imported->hmac = unimported->hmac;
	imported->iv = unimported->iv;
	imported->pub = (const struct leaf_public_data_t *)unimported->payload;
	imported->cipher_text = unimported->payload + unimported->head.pub_len;
	imported->hashes = (const uint8_t (*)[PW_HASH_SIZE])(
			imported->cipher_text + unimported->head.sec_len);
}

/******************************************************************************/
/* Basic operations required by the Merkle tree.
 */

/* Creates an empty merkle_tree with the given parameters. */
static int create_merkle_tree(struct bits_per_level_t bits_per_level,
			      struct height_t height,
			      struct merkle_tree_t *merkle_tree)
{
	uint16_t fan_out = 1 << bits_per_level.v;
	uint8_t temp_hash[PW_HASH_SIZE] = {};
	uint8_t hx;
	uint16_t kx;
	int ret;

	pinweaver_eal_sha256_ctx_t ctx;

	merkle_tree->bits_per_level = bits_per_level;
	merkle_tree->height = height;

	/* Initialize the root hash. */
	for (hx = 0; hx < height.v; ++hx) {
		ret = pinweaver_eal_sha256_init(&ctx);
		if (ret)
			return ret;
		for (kx = 0; kx < fan_out; ++kx) {
			ret = pinweaver_eal_sha256_update(&ctx, temp_hash,
							  PW_HASH_SIZE);
			if (ret) {
				pinweaver_eal_sha256_final(&ctx, temp_hash);
				return ret;
			}
		}
		ret = pinweaver_eal_sha256_final(&ctx, temp_hash);
		if (ret)
			return ret;
	}
	ret = pinweaver_eal_memcpy_s(merkle_tree->root,
				     sizeof(merkle_tree->root), temp_hash,
				     PW_HASH_SIZE);
	if (ret != EC_SUCCESS)
		return ret;

	ret = pinweaver_eal_rand_bytes(
		merkle_tree->key_derivation_nonce,
		sizeof(merkle_tree->key_derivation_nonce));
	if (ret)
		return ret;
	return pinweaver_eal_derive_keys(merkle_tree);
}

static size_t hmac_iv_size(int minor_version)
{
	if (minor_version == 2)
		return PW_HMAC_IV_SIZE_V2;
	else
		return PW_HMAC_IV_SIZE_V1;
}

/* Computes the HMAC for an encrypted leaf using the key in the merkle_tree. */
static int compute_hmac(const struct merkle_tree_t *merkle_tree,
			const struct imported_leaf_data_t *imported_leaf_data,
			uint8_t result[PW_HASH_SIZE])
{
	int ret;
	pinweaver_eal_hmac_sha256_ctx_t hmac;

	ret = pinweaver_eal_hmac_sha256_init(&hmac, merkle_tree->hmac_key,
					     sizeof(merkle_tree->hmac_key));
	if (ret)
		return ret;
	ret = pinweaver_eal_hmac_sha256_update(
		&hmac, imported_leaf_data->head,
		sizeof(*imported_leaf_data->head));
	if (ret) {
		pinweaver_eal_hmac_sha256_final(&hmac, result);
		return ret;
	}
	ret = pinweaver_eal_hmac_sha256_update(&hmac, imported_leaf_data->iv,
					hmac_iv_size(imported_leaf_data->head->leaf_version.minor));
	if (ret) {
		pinweaver_eal_hmac_sha256_final(&hmac, result);
		return ret;
	}
	ret = pinweaver_eal_hmac_sha256_update(
		&hmac, imported_leaf_data->pub,
		imported_leaf_data->head->pub_len);
	if (ret) {
		pinweaver_eal_hmac_sha256_final(&hmac, result);
		return ret;
	}
	ret = pinweaver_eal_hmac_sha256_update(
		&hmac, imported_leaf_data->cipher_text,
		imported_leaf_data->head->sec_len);
	if (ret) {
		pinweaver_eal_hmac_sha256_final(&hmac, result);
		return ret;
	}
	return pinweaver_eal_hmac_sha256_final(&hmac, result);
}

/* Computes the root hash for the specified path and child hash. */
static int compute_root_hash(const struct merkle_tree_t *merkle_tree,
			     struct label_t path,
			     const uint8_t hashes[][PW_HASH_SIZE],
			     const uint8_t child_hash[PW_HASH_SIZE],
			     uint8_t new_root[PW_HASH_SIZE])
{
	/* This is one less than the fan out, the number of sibling hashes. */
	const uint16_t num_aux = (1 << merkle_tree->bits_per_level.v) - 1;
	const uint16_t path_suffix_mask = num_aux;
	uint8_t temp_hash[PW_HASH_SIZE];
	uint8_t hx = 0;
	uint64_t index = path.v;
	int ret;

	if (compute_hash(hashes, num_aux,
			 (struct index_t){ index & path_suffix_mask },
			 child_hash, temp_hash)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	for (hx = 1; hx < merkle_tree->height.v; ++hx) {
		hashes += num_aux;
		index = index >> merkle_tree->bits_per_level.v;
		if (compute_hash(hashes, num_aux,
				 (struct index_t){ index & path_suffix_mask },
				 temp_hash, temp_hash)) {
			return PW_ERR_CRYPTO_FAILURE;
		}
	}
	ret = pinweaver_eal_memcpy_s(new_root, PW_HASH_SIZE, temp_hash,
				     sizeof(temp_hash));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	return EC_SUCCESS;
}

/* Checks to see the specified path is valid. The length of the path should be
 * validated prior to calling this function.
 *
 * Returns 0 on success or an error code otherwise.
 */
static int authenticate_path(const struct merkle_tree_t *merkle_tree,
			     struct label_t path,
			     const uint8_t hashes[][PW_HASH_SIZE],
			     const uint8_t child_hash[PW_HASH_SIZE])
{
	uint8_t parent[PW_HASH_SIZE];

	if (compute_root_hash(merkle_tree, path, hashes, child_hash, parent) !=
	    0)
		return PW_ERR_CRYPTO_FAILURE;
	if (pinweaver_eal_safe_memcmp(parent, merkle_tree->root,
				      sizeof(parent)) != 0)
		return PW_ERR_PATH_AUTH_FAILED;
	return EC_SUCCESS;
}

static void init_wrapped_leaf_data(
		struct wrapped_leaf_data_t *wrapped_leaf_data)
{
	wrapped_leaf_data->head.leaf_version.major = PW_LEAF_MAJOR_VERSION;
	wrapped_leaf_data->head.leaf_version.minor = PW_LEAF_MINOR_VERSION;
	wrapped_leaf_data->head.pub_len = sizeof(wrapped_leaf_data->pub);
	wrapped_leaf_data->head.sec_len =
			sizeof(wrapped_leaf_data->cipher_text);
}

/* Encrypts the leaf meta data. */
static int encrypt_leaf_data(const struct merkle_tree_t *merkle_tree,
			     const struct leaf_data_t *leaf_data,
			     struct wrapped_leaf_data_t *wrapped_leaf_data)
{
	int ret;
	/* Generate a random IV.
	 *
	 * If fields are appended to struct leaf_sensitive_data_t, an encryption
	 * operation should be performed on them reusing the same IV since the
	 * prefix won't change.
	 *
	 * If any data of in the original struct leaf_sensitive_data_t changes,
	 * a new IV should be generated and stored as part of the log for a
	 * replay to be possible.
	 */
	if (pinweaver_eal_rand_bytes(wrapped_leaf_data->iv,
				     sizeof(wrapped_leaf_data->iv))) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	ret = pinweaver_eal_memcpy_s(&wrapped_leaf_data->pub,
				     sizeof(wrapped_leaf_data->pub),
				     &leaf_data->pub, sizeof(leaf_data->pub));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	if (pinweaver_eal_aes256_ctr(merkle_tree->wrap_key,
				      sizeof(merkle_tree->wrap_key),
				      wrapped_leaf_data->iv,
				      &leaf_data->sec,
				      sizeof(leaf_data->sec),
				      wrapped_leaf_data->cipher_text)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	return EC_SUCCESS;
}

/* Decrypts the leaf meta data. */
static int decrypt_leaf_data(
		const struct merkle_tree_t *merkle_tree,
		const struct imported_leaf_data_t *imported_leaf_data,
		struct leaf_data_t *leaf_data)
{
	int ret;
	ret = pinweaver_eal_memcpy_s(&leaf_data->pub, sizeof(leaf_data->pub),
				     imported_leaf_data->pub,
				     MIN(imported_leaf_data->head->pub_len,
					 sizeof(struct leaf_public_data_t)));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	if (pinweaver_eal_aes256_ctr(merkle_tree->wrap_key,
				      sizeof(merkle_tree->wrap_key),
				      imported_leaf_data->iv,
				      imported_leaf_data->cipher_text,
				      sizeof(leaf_data->sec),
				      &leaf_data->sec)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	return EC_SUCCESS;
}

static int handle_leaf_update(
		const struct merkle_tree_t *merkle_tree,
		const struct leaf_data_t *leaf_data,
		const uint8_t hashes[][PW_HASH_SIZE],
		struct wrapped_leaf_data_t *wrapped_leaf_data,
		uint8_t new_root[PW_HASH_SIZE],
		const struct imported_leaf_data_t *optional_old_wrapped_data)
{
	int ret;
	struct imported_leaf_data_t ptrs;

	init_wrapped_leaf_data(wrapped_leaf_data);
	if (optional_old_wrapped_data == NULL) {
		ret = encrypt_leaf_data(merkle_tree, leaf_data,
					wrapped_leaf_data);
		if (ret != EC_SUCCESS)
			return ret;
	} else {
		ret = pinweaver_eal_memcpy_s(wrapped_leaf_data->iv,
					     sizeof(wrapped_leaf_data->iv),
					     optional_old_wrapped_data->iv,
					     sizeof(wrapped_leaf_data->iv));
		if (ret != EC_SUCCESS)
			return PW_ERR_INTERNAL_FAILURE;
		ret = pinweaver_eal_memcpy_s(&wrapped_leaf_data->pub,
					     sizeof(wrapped_leaf_data->pub),
					     &leaf_data->pub,
					     sizeof(leaf_data->pub));
		if (ret != EC_SUCCESS)
			return PW_ERR_INTERNAL_FAILURE;
		ret = pinweaver_eal_memcpy_s(
			wrapped_leaf_data->cipher_text,
			sizeof(wrapped_leaf_data->cipher_text),
			optional_old_wrapped_data->cipher_text,
			sizeof(wrapped_leaf_data->cipher_text));
		if (ret != EC_SUCCESS)
			return PW_ERR_INTERNAL_FAILURE;
	}

	import_leaf((const struct unimported_leaf_data_t *)wrapped_leaf_data,
		    &ptrs);
	ret = compute_hmac(merkle_tree, &ptrs, wrapped_leaf_data->hmac);
	if (ret)
		return ret;

	ret = compute_root_hash(merkle_tree, leaf_data->pub.label, hashes,
				wrapped_leaf_data->hmac, new_root);
	if (ret)
		return ret;

	return EC_SUCCESS;
}

/******************************************************************************/
/* Parameter and state validation functions.
 */

static int validate_tree_parameters(struct bits_per_level_t bits_per_level,
				    struct height_t height)
{
	uint8_t fan_out;

	if (bits_per_level.v < BITS_PER_LEVEL_MIN ||
	    bits_per_level.v > BITS_PER_LEVEL_MAX)
		return PW_ERR_BITS_PER_LEVEL_INVALID;

	fan_out = 1 << bits_per_level.v;

	if (height.v < HEIGHT_MIN ||
	    height.v > HEIGHT_MAX(bits_per_level.v) ||
	    ((fan_out - 1) * height.v) * PW_HASH_SIZE > PW_MAX_PATH_SIZE)
		return PW_ERR_HEIGHT_INVALID;

	return EC_SUCCESS;
}

/* Verifies that merkle_tree has been initialized. */
static int validate_tree(const struct merkle_tree_t *merkle_tree)
{
	if (validate_tree_parameters(merkle_tree->bits_per_level,
				     merkle_tree->height) != EC_SUCCESS)
		return PW_ERR_TREE_INVALID;
	return EC_SUCCESS;
}

/* Checks the following conditions:
 * Extra index fields should be all zero.
 */
static int validate_label(const struct merkle_tree_t *merkle_tree,
			  struct label_t path)
{
	uint8_t shift_by = merkle_tree->bits_per_level.v *
			   merkle_tree->height.v;

	if ((path.v >> shift_by) == 0)
		return EC_SUCCESS;
	return PW_ERR_LABEL_INVALID;
}

/* Checks the following conditions:
 * Columns should be strictly increasing.
 * Zeroes for filler at the end of the delay_schedule are permitted.
 */
static int validate_delay_schedule(const struct delay_schedule_entry_t
				   delay_schedule[PW_SCHED_COUNT])
{
	size_t x;

	/* The first entry should not be useless. */
	if (delay_schedule[0].attempt_count.v == 0 ||
	    delay_schedule[0].time_diff.v == 0)
		return PW_ERR_DELAY_SCHEDULE_INVALID;

	for (x = PW_SCHED_COUNT - 1; x > 0; --x) {
		if (delay_schedule[x].attempt_count.v == 0) {
			if (delay_schedule[x].time_diff.v != 0)
				return PW_ERR_DELAY_SCHEDULE_INVALID;
		} else if (delay_schedule[x].attempt_count.v <=
				delay_schedule[x - 1].attempt_count.v ||
				delay_schedule[x].time_diff.v <=
				delay_schedule[x - 1].time_diff.v) {
			return PW_ERR_DELAY_SCHEDULE_INVALID;
		}
	}
	return EC_SUCCESS;
}

static int validate_pcr_value(const struct valid_pcr_value_t
			      valid_pcr_criteria[PW_MAX_PCR_CRITERIA_COUNT])
{
	size_t index;
	uint8_t sha256_of_selected_pcr[SHA256_DIGEST_SIZE];

	for (index = 0; index < PW_MAX_PCR_CRITERIA_COUNT; ++index) {
		/* The criteria with bitmask[0] = bitmask[1] = 0 is considered
		 * the end of list criteria. If it happens that the first
		 * bitmask is zero, we consider that no criteria has to be
		 * satisfied and return success in that case.
		 */
		if (valid_pcr_criteria[index].bitmask[0] == 0 &&
		    valid_pcr_criteria[index].bitmask[1] == 0) {
			if (index == 0)
				return EC_SUCCESS;

			return PW_ERR_PCR_NOT_MATCH;
		}

		if (pinweaver_eal_get_current_pcr_digest(
				valid_pcr_criteria[index].bitmask,
				sha256_of_selected_pcr)) {
			PINWEAVER_EAL_INFO(
				"PinWeaver: Read PCR error, bitmask: %d, %d",
				valid_pcr_criteria[index].bitmask[0],
				valid_pcr_criteria[index].bitmask[1]);
			return PW_ERR_PCR_NOT_MATCH;
		}

		/* Check if the curent PCR digest is the same as expected by
		 * criteria.
		 */
		if (pinweaver_eal_safe_memcmp(sha256_of_selected_pcr,
					      valid_pcr_criteria[index].digest,
					      SHA256_DIGEST_SIZE) == 0) {
			return EC_SUCCESS;
		}
	}

	PINWEAVER_EAL_INFO("PinWeaver: No criteria matches PCR values");
	return PW_ERR_PCR_NOT_MATCH;
}

static uint32_t expected_payload_len(int minor_version)
{
	switch (minor_version) {
	case 0:
		return PW_LEAF_PAYLOAD_SIZE - PW_VALID_PCR_CRITERIA_SIZE
			- PW_EXPIRATION_DATA_SIZE - sizeof(struct pw_leaf_type_t);
	case 1:
		return PW_LEAF_PAYLOAD_SIZE - PW_EXPIRATION_DATA_SIZE
			- sizeof(struct pw_leaf_type_t);
	case PW_LEAF_MINOR_VERSION:
		return PW_LEAF_PAYLOAD_SIZE;
	default:
		return 0;
	}
}

static int validate_leaf_header(const struct leaf_header_t *head,
				uint16_t payload_len, uint16_t aux_hash_len)
{
	uint32_t leaf_payload_len = head->pub_len + head->sec_len;

	if (head->leaf_version.major != PW_LEAF_MAJOR_VERSION)
		return PW_ERR_LEAF_VERSION_MISMATCH;

	if (head->leaf_version.minor <= PW_LEAF_MINOR_VERSION &&
	    leaf_payload_len !=
	    expected_payload_len(head->leaf_version.minor)) {
		return PW_ERR_LENGTH_INVALID;
	}

	if (payload_len != leaf_payload_len + aux_hash_len * PW_HASH_SIZE)
		return PW_ERR_LENGTH_INVALID;

	if (head->sec_len < sizeof(struct leaf_sensitive_data_t))
		return PW_ERR_LENGTH_INVALID;

	return EC_SUCCESS;
}

/* Common validation for requests that include a path to authenticate. */
static int validate_request_with_path(const struct merkle_tree_t *merkle_tree,
				      struct label_t path,
				      const uint8_t hashes[][PW_HASH_SIZE],
				      const uint8_t hmac[PW_HASH_SIZE])
{
	int ret;

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	ret = validate_label(merkle_tree, path);
	if (ret != EC_SUCCESS)
		return ret;

	return authenticate_path(merkle_tree, path, hashes, hmac);
}

/* Common validation for requests that import a leaf. */
static int validate_request_with_wrapped_leaf(
		const struct merkle_tree_t *merkle_tree,
		uint16_t payload_len,
		const struct unimported_leaf_data_t *unimported_leaf_data,
		struct imported_leaf_data_t *imported_leaf_data,
		struct leaf_data_t *leaf_data)
{
	int ret;
	uint8_t hmac[PW_HASH_SIZE];

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	ret = validate_leaf_header(&unimported_leaf_data->head, payload_len,
				   get_path_auxiliary_hash_count(merkle_tree));
	if (ret != EC_SUCCESS)
		return ret;

	import_leaf(unimported_leaf_data, imported_leaf_data);
	ret = validate_request_with_path(merkle_tree,
					 imported_leaf_data->pub->label,
					 imported_leaf_data->hashes,
					 imported_leaf_data->hmac);
	if (ret != EC_SUCCESS)
		return ret;

	ret = compute_hmac(merkle_tree, imported_leaf_data, hmac);
	if (ret != EC_SUCCESS)
		return ret;
	/* Safe memcmp is used here to prevent an attacker from being able to
	 * brute force a valid HMAC for a crafted wrapped_leaf_data.
	 * memcmp provides an attacker a timing side-channel they can use to
	 * determine how much of a prefix is correct.
	 */
	if (pinweaver_eal_safe_memcmp(hmac, unimported_leaf_data->hmac,
				      sizeof(hmac)))
		return PW_ERR_HMAC_AUTH_FAILED;

	ret = decrypt_leaf_data(merkle_tree, imported_leaf_data, leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	/* The code below handles version upgrades. */
	if (unimported_leaf_data->head.leaf_version.minor == 0 &&
	    unimported_leaf_data->head.leaf_version.major == 0) {
		/* Populate the leaf_data with default pcr value */
		memset(&leaf_data->pub.valid_pcr_criteria, 0,
		       PW_VALID_PCR_CRITERIA_SIZE);
	}

	if (unimported_leaf_data->head.leaf_version.major == 0 &&
	    unimported_leaf_data->head.leaf_version.minor <= 1) {
		/* Populate the leaf_data with default expiration timestamp value,
		 * expiration_delay_s will be set to 0 too, meaning the leaf won't
		 * expire.
		 */
		memset(&leaf_data->pub.expiration_ts, 0, PW_EXPIRATION_DATA_SIZE);
		/* Populate the leaf_data with default leaf type. */
		leaf_data->pub.leaf_type.v = PW_LEAF_TYPE_NORMAL;
	}

	return EC_SUCCESS;
}

/* Sets the value of ts to the current notion of time. */
static void update_timestamp(struct pw_timestamp_t *ts)
{
	ts->timer_value = pinweaver_eal_seconds_since_boot();
	ts->boot_count = pw_restart_count;
}

/* Checks if an auth attempt can be made or not based on the delay schedule:
 * - EC_SUCCESS is returned when a new attempt can be made,
 * - PW_ERR_EXPIRED is returned if the leaf is expired, and otherwise
 * - PW_ERR_RATE_LIMIT_REACHED is returned with seconds_to_wait updated to
 *   the remaining waiting time required.
 */
static int test_rate_limit(struct leaf_data_t *leaf_data,
			   struct time_diff_t *seconds_to_wait)
{
	uint64_t ready_time;
	uint8_t x;
	struct pw_timestamp_t current_time;
	struct time_diff_t delay = {0};

	update_timestamp(&current_time);

	if (leaf_data->pub.expiration_delay_s.v != 0 &&
	    (leaf_data->pub.expiration_ts.boot_count != current_time.boot_count ||
	    leaf_data->pub.expiration_ts.timer_value <= current_time.timer_value)) {
		return PW_ERR_EXPIRED;
	}

	/* This loop ends when x is one greater than the index that applies. */
	for (x = 0; x < ARRAY_SIZE(leaf_data->pub.delay_schedule); ++x) {
		/* Stop if a null entry is reached. The first part of the delay
		 * schedule has a list of increasing (attempt_count, time_diff)
		 * pairs with any unused entries zeroed out at the end.
		 */
		if (leaf_data->pub.delay_schedule[x].attempt_count.v == 0)
			break;

		/* Stop once a delay schedule entry is reached whose
		 * threshold is greater than the current number of
		 * attempts.
		 */
		if (leaf_data->pub.attempt_count.v <
		    leaf_data->pub.delay_schedule[x].attempt_count.v)
			break;
	}

	/* If the first threshold was greater than the current number of
	 * attempts, there is no delay. Otherwise, grab the delay from the
	 * entry prior to the one that was too big.
	 */
	if (x > 0)
		delay = leaf_data->pub.delay_schedule[x - 1].time_diff;

	if (delay.v == 0)
		return EC_SUCCESS;

	if (delay.v == PW_BLOCK_ATTEMPTS) {
		seconds_to_wait->v = PW_BLOCK_ATTEMPTS;
		return PW_ERR_RATE_LIMIT_REACHED;
	}

	if (leaf_data->pub.last_access_ts.boot_count == current_time.boot_count)
		ready_time = delay.v + leaf_data->pub.last_access_ts.timer_value;
	else
		ready_time = delay.v;

	if (current_time.timer_value >= ready_time)
		return EC_SUCCESS;

	seconds_to_wait->v = ready_time - current_time.timer_value;
	return PW_ERR_RATE_LIMIT_REACHED;
}

/******************************************************************************/
/* Logging implementation.
 */

/* Once the storage version is incremented, the update code needs to be written
 * to handle differences in the structs.
 *
 * See the two comments "Add storage format updates here." below.
 */
BUILD_ASSERT(PW_STORAGE_VERSION == 0);

void force_restart_count(uint32_t mock_value)
{
	pw_restart_count = mock_value;
}

/* Returns EC_SUCCESS if the root hash was found. Sets *index to the first index
 * of the log entry with a matching root hash, or the index of the last valid
 * entry.
 */
static int find_relevant_entry(const struct pw_log_storage_t *log,
			       const uint8_t root[PW_HASH_SIZE], int *index)
{
	/* Find the relevant log entry. */
	for (*index = 0; *index < PW_LOG_ENTRY_COUNT; ++*index) {
		if (log->entries[*index].type.v == LOG_PW_MT_INVALID)
			break;
		if (pinweaver_eal_safe_memcmp(root, log->entries[*index].root,
					      PW_HASH_SIZE) == 0)
			return EC_SUCCESS;
	}
	--*index;
	return PW_ERR_ROOT_NOT_FOUND;
}

/* TODO(apronin): get rid of temporary redirect methods */

static int load_log_data(struct pw_log_storage_t *log)
{
	return pinweaver_eal_storage_get_log(log);
}

int store_log_data(const struct pw_log_storage_t *log)
{
	return pinweaver_eal_storage_set_log(log);
}

static int load_merkle_tree(struct merkle_tree_t *merkle_tree)
{
	int ret;

	PINWEAVER_EAL_INFO("PinWeaver: Loading Tree!");

	/* Handle the immutable data. */
	{
		struct pw_long_term_storage_t tree;

		ret = pinweaver_eal_storage_get_tree_data(&tree);
		if (ret != EC_SUCCESS)
			return ret;

		merkle_tree->bits_per_level = tree.bits_per_level;
		merkle_tree->height = tree.height;
		ret = pinweaver_eal_memcpy_s(
			merkle_tree->key_derivation_nonce,
			sizeof(merkle_tree->key_derivation_nonce),
			tree.key_derivation_nonce,
			sizeof(tree.key_derivation_nonce));
		if (ret != EC_SUCCESS)
			return ret;
		ret = pinweaver_eal_derive_keys(merkle_tree);
		if (ret != EC_SUCCESS)
			return ret;
	}

	/* Handle the root hash. */
	{
		ret = pinweaver_eal_storage_init_state(merkle_tree->root,
						       &pw_restart_count);
		if (ret != EC_SUCCESS)
			return ret;
	}

	PINWEAVER_EAL_INFO("PinWeaver: Loaded Tree. restart_count = %d",
		pw_restart_count);

	return EC_SUCCESS;
}

/* This should only be called when a new tree is created. */
int store_merkle_tree(const struct merkle_tree_t *merkle_tree)
{
	int ret;

	/* Handle the immutable data. */
	{
		struct pw_long_term_storage_t data;

		data.storage_version = PW_STORAGE_VERSION;
		data.bits_per_level = merkle_tree->bits_per_level;
		data.height = merkle_tree->height;
		ret = pinweaver_eal_memcpy_s(data.key_derivation_nonce,
					     sizeof(data.key_derivation_nonce),
					     merkle_tree->key_derivation_nonce,
					     sizeof(data.key_derivation_nonce));
		if (ret != EC_SUCCESS)
			return ret;

		ret = pinweaver_eal_storage_set_tree_data(&data);
		if (ret != EC_SUCCESS)
			return ret;
	}

	/* Handle the root hash. */
	{
		struct pw_log_storage_t log = {};
		struct pw_get_log_entry_t *entry = log.entries;

		log.storage_version = PW_STORAGE_VERSION;
		entry->type.v = LOG_PW_RESET_TREE;
		ret = pinweaver_eal_memcpy_s(entry->root, sizeof(entry->root),
					     merkle_tree->root,
					     sizeof(merkle_tree->root));
		if (ret != EC_SUCCESS)
			return ret;

		ret = store_log_data(&log);
		if (ret == EC_SUCCESS)
			pw_restart_count = 0;
		return ret;
	}

}

static int log_roll_for_append(struct pw_log_storage_t *log)
{
	int ret;

	ret = load_log_data(log);
	if (ret != EC_SUCCESS)
		return ret;

	memmove(&log->entries[1], &log->entries[0],
		sizeof(log->entries[0]) * (PW_LOG_ENTRY_COUNT - 1));
	memset(&log->entries[0], 0, sizeof(log->entries[0]));
	return EC_SUCCESS;
}

int log_insert_leaf(struct label_t label, const uint8_t root[PW_HASH_SIZE],
		    const uint8_t hmac[PW_HASH_SIZE])
{
	int ret;
	struct pw_log_storage_t log;
	struct pw_get_log_entry_t *entry = log.entries;

	ret = log_roll_for_append(&log);
	if (ret != EC_SUCCESS)
		return ret;

	entry->type.v = LOG_PW_INSERT_LEAF;
	entry->label.v = label.v;
	ret = pinweaver_eal_memcpy_s(entry->root, sizeof(entry->root), root,
				     sizeof(entry->root));
	if (ret != EC_SUCCESS)
		return ret;
	ret = pinweaver_eal_memcpy_s(entry->leaf_hmac, sizeof(entry->leaf_hmac),
				     hmac, sizeof(entry->leaf_hmac));
	if (ret != EC_SUCCESS)
		return ret;

	return store_log_data(&log);
}

int log_remove_leaf(struct label_t label, const uint8_t root[PW_HASH_SIZE])
{
	int ret;
	struct pw_log_storage_t log;
	struct pw_get_log_entry_t *entry = log.entries;

	ret = log_roll_for_append(&log);
	if (ret != EC_SUCCESS)
		return ret;

	entry->type.v = LOG_PW_REMOVE_LEAF;
	entry->label.v = label.v;
	ret = pinweaver_eal_memcpy_s(entry->root, sizeof(entry->root), root,
				     sizeof(entry->root));
	if (ret != EC_SUCCESS)
		return ret;

	return store_log_data(&log);
}

int log_auth(struct label_t label, const uint8_t root[PW_HASH_SIZE], int code,
	     struct pw_timestamp_t last_access_ts,
	     struct pw_timestamp_t expiration_ts)
{
	int ret;
	struct pw_log_storage_t log;
	struct pw_get_log_entry_t *entry = log.entries;

	ret = log_roll_for_append(&log);
	if (ret != EC_SUCCESS)
		return ret;

	entry->type.v = LOG_PW_TRY_AUTH;
	entry->label.v = label.v;
	ret = pinweaver_eal_memcpy_s(entry->root, sizeof(entry->root), root,
				     sizeof(entry->root));
	if (ret != EC_SUCCESS)
		return ret;
	entry->return_code = code;
	ret = pinweaver_eal_memcpy_s(&entry->last_access_ts,
				     sizeof(entry->last_access_ts), &last_access_ts,
				     sizeof(entry->last_access_ts));
	if (ret != EC_SUCCESS)
		return ret;
	ret = pinweaver_eal_memcpy_s(&entry->expiration_ts,
				     sizeof(entry->expiration_ts), &expiration_ts,
				     sizeof(entry->expiration_ts));
	if (ret != EC_SUCCESS)
		return ret;

	return store_log_data(&log);
}

/******************************************************************************/
/* Per-request-type handler implementations.
 */

static int pw_handle_reset_tree(struct merkle_tree_t *merkle_tree,
				const pw_request_reset_tree_t *request,
				uint16_t req_size)
{
	struct merkle_tree_t new_tree = {};
	int ret;

	if (req_size != sizeof(*request))
		return PW_ERR_LENGTH_INVALID;

	ret = validate_tree_parameters(request->bits_per_level,
				       request->height);
	if (ret != EC_SUCCESS)
		return ret;

	ret = create_merkle_tree(request->bits_per_level, request->height,
				 &new_tree);
	if (ret != EC_SUCCESS)
		return ret;

	ret = store_merkle_tree(&new_tree);
	if (ret != EC_SUCCESS)
		return ret;

	ret = pinweaver_eal_memcpy_s(merkle_tree, sizeof(*merkle_tree),
				     &new_tree, sizeof(new_tree));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	return EC_SUCCESS;
}

static int generate_ba_secrets(const struct merkle_tree_t *merkle_tree,
				 uint8_t auth_channel,
				 uint8_t low_entropy_secret[PW_SECRET_SIZE],
				 uint8_t high_entropy_secret[PW_SECRET_SIZE])
{
	int ret;
	struct pw_ba_pk_t pk;
	pinweaver_eal_hmac_sha256_ctx_t hmac;

	if (auth_channel >= PW_BA_PK_ENTRY_COUNT) {
		return PW_ERR_BIO_AUTH_CHANNEL_INVALID;
	}

	/* An established Pk on the specified auth channel is required
	 * to create a biometrics limiter leaf.
	 */
	ret = pinweaver_eal_storage_get_ba_pk(auth_channel, &pk);
	if (ret != EC_SUCCESS)
		return ret;

	/* hmac-sha256 Pk and auth_channel into LEC. */
	if (pinweaver_eal_hmac_sha256_init(&hmac, merkle_tree->hmac_key,
				sizeof(merkle_tree->hmac_key))) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_update(&hmac, pk.key, PW_SECRET_SIZE)) {
		pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_update(&hmac, &auth_channel,
				sizeof(auth_channel))) {
		pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret))
		return PW_ERR_CRYPTO_FAILURE;

	/* Randomly generate LabelSeed, which is HEC too. */
	if (pinweaver_eal_rand_bytes(high_entropy_secret, PW_SECRET_SIZE))
		return PW_ERR_CRYPTO_FAILURE;

	return EC_SUCCESS;
}

static int pw_handle_insert_leaf(struct merkle_tree_t *merkle_tree,
				 pw_request_insert_leaf_t *request,
				 uint16_t req_size,
				 pw_response_insert_leaf_t *response,
				 uint16_t *response_size)
{
	int ret = EC_SUCCESS;
	struct leaf_data_t leaf_data = {};
	struct wrapped_leaf_data_t wrapped_leaf_data = {};
	const uint8_t empty_hash[PW_HASH_SIZE] = {};
	uint8_t new_root[PW_HASH_SIZE];
	uint32_t delay_s;

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	if (req_size != sizeof(*request) +
			get_path_auxiliary_hash_count(merkle_tree) *
			PW_HASH_SIZE)
		return PW_ERR_LENGTH_INVALID;

	ret = validate_request_with_path(merkle_tree, request->label,
					 request->path_hashes, empty_hash);
	if (ret != EC_SUCCESS)
		return ret;

	ret = validate_delay_schedule(request->delay_schedule);
	if (ret != EC_SUCCESS)
		return ret;

	memset(&leaf_data, 0, sizeof(leaf_data));
	leaf_data.pub.label.v = request->label.v;
	ret = pinweaver_eal_memcpy_s(&leaf_data.pub.valid_pcr_criteria,
				     sizeof(leaf_data.pub.valid_pcr_criteria),
				     request->valid_pcr_criteria,
				     sizeof(request->valid_pcr_criteria));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	ret = pinweaver_eal_memcpy_s(&leaf_data.pub.delay_schedule,
				     sizeof(leaf_data.pub.delay_schedule),
				     &request->delay_schedule,
				     sizeof(request->delay_schedule));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	if (request->expiration_delay_s.v != 0) {
		update_timestamp(&leaf_data.pub.expiration_ts);
		delay_s = request->expiration_delay_s.v;
		if (leaf_data.pub.expiration_ts.timer_value <= UINT64_MAX - delay_s) {
			leaf_data.pub.expiration_ts.timer_value += delay_s;
		} else {
			// Timer has become too large, and expiration won't work properly.
			return PW_ERR_INTERNAL_FAILURE;
		}
		leaf_data.pub.expiration_delay_s.v = delay_s;
	}

	leaf_data.pub.leaf_type.v = request->leaf_type.v;
	if (request->leaf_type.v == PW_LEAF_TYPE_BIOMETRICS) {
		/* LEC and HEC need to be populated. */
		ret = generate_ba_secrets(
			merkle_tree,
			request->auth_channel,
			request->low_entropy_secret,
			request->high_entropy_secret);
		if (ret != EC_SUCCESS)
			return ret;
	} else if (request->leaf_type.v != PW_LEAF_TYPE_NORMAL) {
		return PW_ERR_INTERNAL_FAILURE;
	}

	ret = pinweaver_eal_memcpy_s(&leaf_data.sec.low_entropy_secret,
				     sizeof(leaf_data.sec.low_entropy_secret),
				     &request->low_entropy_secret,
				     sizeof(request->low_entropy_secret));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	ret = pinweaver_eal_memcpy_s(&leaf_data.sec.high_entropy_secret,
				     sizeof(leaf_data.sec.high_entropy_secret),
				     &request->high_entropy_secret,
				     sizeof(request->high_entropy_secret));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	ret = pinweaver_eal_memcpy_s(&leaf_data.sec.reset_secret,
				     sizeof(leaf_data.sec.reset_secret),
				     &request->reset_secret,
				     sizeof(request->reset_secret));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = handle_leaf_update(merkle_tree, &leaf_data, request->path_hashes,
				 &wrapped_leaf_data, new_root, NULL);
	if (ret != EC_SUCCESS)
		return ret;

	ret = log_insert_leaf(request->label, new_root,
			      wrapped_leaf_data.hmac);
	if (ret != EC_SUCCESS)
		return ret;

	ret = pinweaver_eal_memcpy_s(merkle_tree->root,
				     sizeof(merkle_tree->root), new_root,
				     sizeof(new_root));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = pinweaver_eal_memcpy_s(&response->unimported_leaf_data,
				     sizeof(wrapped_leaf_data),
				     &wrapped_leaf_data,
				     sizeof(wrapped_leaf_data));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	*response_size = sizeof(*response) + PW_LEAF_PAYLOAD_SIZE;

	return ret;
}

static int pw_handle_remove_leaf(struct merkle_tree_t *merkle_tree,
				 const pw_request_remove_leaf_t *request,
				 uint16_t req_size)
{
	int ret = EC_SUCCESS;
	const uint8_t empty_hash[PW_HASH_SIZE] = {};
	uint8_t new_root[PW_HASH_SIZE];

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	if (req_size != sizeof(*request) +
			get_path_auxiliary_hash_count(merkle_tree) *
			PW_HASH_SIZE)
		return PW_ERR_LENGTH_INVALID;

	ret = validate_request_with_path(merkle_tree, request->leaf_location,
					 request->path_hashes,
					 request->leaf_hmac);
	if (ret != EC_SUCCESS)
		return ret;

	ret = compute_root_hash(merkle_tree, request->leaf_location,
				request->path_hashes, empty_hash, new_root);
	if (ret != EC_SUCCESS)
		return ret;

	ret = log_remove_leaf(request->leaf_location, new_root);
	if (ret != EC_SUCCESS)
		return ret;

	ret = pinweaver_eal_memcpy_s(merkle_tree->root,
				     sizeof(merkle_tree->root), new_root,
				     sizeof(new_root));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	return ret;
}

/* Processes a try_auth request.
 *
 * The valid fields in response based on return code are:
 *   EC_SUCCESS                 ->  unimported_leaf_data and high_entropy_secret
 *   PW_ERR_RATE_LIMIT_REACHED  ->  seconds_to_wait
 *   PW_ERR_LOWENT_AUTH_FAILED  ->  unimported_leaf_data
 */
static int pw_handle_try_auth(struct merkle_tree_t *merkle_tree,
			      const pw_request_try_auth_t *request,
			      uint16_t req_size,
			      pw_response_try_auth_t *response,
			      uint16_t *data_length)
{
	int ret = EC_SUCCESS;
	struct leaf_data_t leaf_data = {};
	struct imported_leaf_data_t imported_leaf_data;
	struct wrapped_leaf_data_t wrapped_leaf_data = {};
	struct time_diff_t seconds_to_wait;
	struct pw_timestamp_t expiration_ts = {};
	uint8_t zeros[PW_SECRET_SIZE] = {};
	uint8_t new_root[PW_HASH_SIZE];

	/* These variables help eliminate the possibility of a timing side
	 * channel that would allow an attacker to prevent the log write.
	 */
	volatile int auth_result;

	volatile struct {
		uint32_t attempts;
		int ret;
		uint8_t *secret;
		uint8_t *reset_secret;
	} results_table[2] = {
			{ 0, PW_ERR_LOWENT_AUTH_FAILED, zeros, zeros },
			{ 0, EC_SUCCESS, leaf_data.sec.high_entropy_secret,
			  leaf_data.sec.reset_secret },
	};

	if (req_size < sizeof(*request))
		return PW_ERR_LENGTH_INVALID;

	ret = validate_request_with_wrapped_leaf(
			merkle_tree, req_size - sizeof(*request),
			&request->unimported_leaf_data, &imported_leaf_data,
			&leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	/* Check if at least one PCR criteria is satisfied if the leaf is
	 * bound to PCR.
	 */
	ret = validate_pcr_value(leaf_data.pub.valid_pcr_criteria);
	if (ret != EC_SUCCESS)
		return ret;

	ret = test_rate_limit(&leaf_data, &seconds_to_wait);
	if (ret != EC_SUCCESS) {
		*data_length = sizeof(*response) + PW_LEAF_PAYLOAD_SIZE;
		memset(response, 0, *data_length);
		if (ret == PW_ERR_RATE_LIMIT_REACHED) {
			pinweaver_eal_memcpy_s(&response->seconds_to_wait,
				sizeof(response->seconds_to_wait),
				&seconds_to_wait,
				sizeof(seconds_to_wait));
		}
		return ret;
	}

	update_timestamp(&leaf_data.pub.last_access_ts);

	/* Precompute the failed attempts. */
	results_table[0].attempts = leaf_data.pub.attempt_count.v;
	if (results_table[0].attempts != UINT32_MAX)
		++results_table[0].attempts;
	if (leaf_data.pub.leaf_type.v == PW_LEAF_TYPE_BIOMETRICS) {
		/* Always increase attempts for biometrics limiter leaf type. */
		results_table[1].ret = PW_ERR_SUCCESS_WITH_INCREMENT;
		results_table[1].attempts = results_table[0].attempts;
	}

	/**********************************************************************/
	/* After this:
	 * 1) results_table should not be changed;
	 * 2) the runtime of the code paths for failed and successful
	 *    authentication attempts should not diverge.
	 */
	auth_result = pinweaver_eal_safe_memcmp(
			request->low_entropy_secret,
			leaf_data.sec.low_entropy_secret,
			sizeof(request->low_entropy_secret)) == 0;
	leaf_data.pub.attempt_count.v = results_table[auth_result].attempts;

	/* This has a non-constant time path, but it doesn't convey information
	 * about whether a PW_ERR_LOWENT_AUTH_FAILED happened or not.
	 */
	ret = handle_leaf_update(merkle_tree, &leaf_data,
				 imported_leaf_data.hashes, &wrapped_leaf_data,
				 new_root, &imported_leaf_data);
	if (ret != EC_SUCCESS)
		return ret;


	expiration_ts = leaf_data.pub.expiration_ts;
	ret = log_auth(wrapped_leaf_data.pub.label, new_root,
		       results_table[auth_result].ret, leaf_data.pub.last_access_ts,
		       expiration_ts);
	if (ret != EC_SUCCESS) {
		pinweaver_eal_memcpy_s(new_root, sizeof(new_root),
				       merkle_tree->root,
				       sizeof(merkle_tree->root));
		return ret;
	}
	/**********************************************************************/
	/* At this point the log should be written so it should be safe for the
	 * runtime of the code paths to diverge.
	 */

	ret = pinweaver_eal_memcpy_s(merkle_tree->root,
				     sizeof(merkle_tree->root), new_root,
				     sizeof(new_root));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	*data_length = sizeof(*response) + PW_LEAF_PAYLOAD_SIZE;
	memset(response, 0, *data_length);

	ret = pinweaver_eal_memcpy_s(&response->unimported_leaf_data,
				     sizeof(wrapped_leaf_data),
				     &wrapped_leaf_data,
				     sizeof(wrapped_leaf_data));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = pinweaver_eal_memcpy_s(&response->high_entropy_secret,
				     sizeof(response->high_entropy_secret),
				     results_table[auth_result].secret,
				     sizeof(response->high_entropy_secret));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = pinweaver_eal_memcpy_s(&response->reset_secret,
				     sizeof(response->reset_secret),
				     results_table[auth_result].reset_secret,
				     sizeof(response->reset_secret));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	return results_table[auth_result].ret;
}

static int pw_handle_reset_auth(struct merkle_tree_t *merkle_tree,
				const pw_request_reset_auth_t *request,
				uint16_t req_size,
				pw_response_reset_auth_t *response,
				uint16_t *response_size)
{
	int ret = EC_SUCCESS;
	struct leaf_data_t leaf_data = {};
	struct imported_leaf_data_t imported_leaf_data;
	struct wrapped_leaf_data_t wrapped_leaf_data = {};
	struct pw_timestamp_t expiration_ts = {};
	uint8_t new_root[PW_HASH_SIZE];
	uint32_t delay_s;

	if (req_size < sizeof(*request))
		return PW_ERR_LENGTH_INVALID;

	ret = validate_request_with_wrapped_leaf(
			merkle_tree, req_size - sizeof(*request),
			&request->unimported_leaf_data, &imported_leaf_data,
			&leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	/* Safe memcmp is used here to prevent an attacker from being able to
	 * brute force the reset secret and use it to unlock the leaf.
	 * memcmp provides an attacker a timing side-channel they can use to
	 * determine how much of a prefix is correct.
	 */
	if (pinweaver_eal_safe_memcmp(request->reset_secret,
				      leaf_data.sec.reset_secret,
				      sizeof(request->reset_secret)) != 0)
		return PW_ERR_RESET_AUTH_FAILED;

	leaf_data.pub.attempt_count.v = 0;

	if (request->strong_reset && leaf_data.pub.expiration_delay_s.v != 0) {
		update_timestamp(&leaf_data.pub.expiration_ts);
		delay_s = leaf_data.pub.expiration_delay_s.v;
		if (leaf_data.pub.expiration_ts.timer_value <= UINT64_MAX - delay_s) {
			leaf_data.pub.expiration_ts.timer_value += delay_s;
		} else {
			leaf_data.pub.expiration_ts.timer_value = UINT64_MAX;
		}
	}

	ret = handle_leaf_update(merkle_tree, &leaf_data,
				 imported_leaf_data.hashes, &wrapped_leaf_data,
				 new_root, &imported_leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	expiration_ts = leaf_data.pub.expiration_ts;
	ret = log_auth(leaf_data.pub.label, new_root, ret,
		       leaf_data.pub.last_access_ts, expiration_ts);
	if (ret != EC_SUCCESS)
		return ret;

	ret = pinweaver_eal_memcpy_s(merkle_tree->root,
				     sizeof(merkle_tree->root), new_root,
				     sizeof(new_root));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = pinweaver_eal_memcpy_s(&response->unimported_leaf_data,
				     sizeof(wrapped_leaf_data),
				     &wrapped_leaf_data,
				     sizeof(wrapped_leaf_data));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	*response_size = sizeof(*response) + PW_LEAF_PAYLOAD_SIZE;

	return ret;
}

static int pw_handle_get_log(const struct merkle_tree_t *merkle_tree,
			     const pw_request_get_log_t *request,
			     uint16_t req_size,
			     struct pw_get_log_entry_t response[],
			     uint16_t *response_size)
{
	int ret;
	int x;
	struct pw_log_storage_t log;

	if (req_size != sizeof(*request))
		return PW_ERR_LENGTH_INVALID;

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	ret = load_log_data(&log);
	if (ret != EC_SUCCESS)
		return ret;

	/* Find the relevant log entry. The return value isn't used because if
	 * the entry isn't found the entire log is returned. This makes it
	 * easier to recover when the log is too short.
	 *
	 * Here is an example:
	 * 50 attempts have been made against a leaf that becomes out of sync
	 * because of a disk flush failing. The copy of the leaf on disk is
	 * behind by 50 and the log contains less than 50 entries. The CrOS
	 * implementation can check the public parameters of the local copy with
	 * the log entry to determine that leaf is out of sync. It can then send
	 * any valid copy of that leaf with a log replay request that will only
	 * succeed if the HMAC of the resulting leaf matches the log entry.
	 */
	find_relevant_entry(&log, request->root, &x);
	/* If there are no valid entries, return. */
	if (x < 0)
		return EC_SUCCESS;

	/* Copy the entries in reverse order. */
	while (1) {
		ret = pinweaver_eal_memcpy_s(&response[x], sizeof(response[x]),
					     &log.entries[x],
					     sizeof(log.entries[x]));
		if (ret != EC_SUCCESS)
			return PW_ERR_INTERNAL_FAILURE;
		*response_size += sizeof(log.entries[x]);
		if (x == 0)
			break;
		--x;
	}

	return EC_SUCCESS;
}

static int pw_handle_log_replay(const struct merkle_tree_t *merkle_tree,
				const pw_request_log_replay_t *request,
				uint16_t req_size,
				pw_response_log_replay_t *response,
				uint16_t *response_size)
{
	int ret;
	int x;
	struct pw_log_storage_t log;
	struct leaf_data_t leaf_data = {};
	struct imported_leaf_data_t imported_leaf_data;
	struct wrapped_leaf_data_t wrapped_leaf_data = {};
	uint8_t hmac[PW_HASH_SIZE];
	uint8_t root[PW_HASH_SIZE];

	if (req_size < sizeof(*request))
		return PW_ERR_LENGTH_INVALID;

	ret = validate_tree(merkle_tree);
	if (ret != EC_SUCCESS)
		return ret;

	/* validate_request_with_wrapped_leaf() isn't used here because the
	 * path validation is delayed to allow any valid copy of the same leaf
	 * to be used in the replay operation as long as the result passes path
	 * validation.
	 */
	ret = validate_leaf_header(&request->unimported_leaf_data.head,
				   req_size - sizeof(*request),
				   get_path_auxiliary_hash_count(merkle_tree));
	if (ret != EC_SUCCESS)
		return ret;

	import_leaf(&request->unimported_leaf_data, &imported_leaf_data);

	ret = load_log_data(&log);
	if (ret != EC_SUCCESS)
		return ret;

	/* Find the relevant log entry. */
	ret = find_relevant_entry(&log, request->log_root, &x);
	if (ret != EC_SUCCESS)
		return ret;

	/* The other message types don't need to be handled by Cr50. */
	if (log.entries[x].type.v != LOG_PW_TRY_AUTH)
		return PW_ERR_TYPE_INVALID;

	ret = compute_hmac(merkle_tree, &imported_leaf_data, hmac);
	if (ret != EC_SUCCESS)
		return ret;
	if (pinweaver_eal_safe_memcmp(hmac,
				      request->unimported_leaf_data.hmac,
				      sizeof(hmac)))
		return PW_ERR_HMAC_AUTH_FAILED;

	ret = decrypt_leaf_data(merkle_tree, &imported_leaf_data, &leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	if (leaf_data.pub.label.v != log.entries[x].label.v)
		return PW_ERR_LABEL_INVALID;

	/* Update the metadata to match the log. */
	if (log.entries[x].return_code == EC_SUCCESS)
		leaf_data.pub.attempt_count.v = 0;
	else
		++leaf_data.pub.attempt_count.v;
	ret = pinweaver_eal_memcpy_s(&leaf_data.pub.last_access_ts,
				     sizeof(leaf_data.pub.last_access_ts),
				     &log.entries[x].last_access_ts,
				     sizeof(leaf_data.pub.last_access_ts));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;
	ret = pinweaver_eal_memcpy_s(&leaf_data.pub.expiration_ts,
				     sizeof(leaf_data.pub.expiration_ts),
				     &log.entries[x].expiration_ts,
				     sizeof(leaf_data.pub.expiration_ts));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	ret = handle_leaf_update(merkle_tree, &leaf_data,
				 imported_leaf_data.hashes, &wrapped_leaf_data,
				 root, &imported_leaf_data);
	if (ret != EC_SUCCESS)
		return ret;

	if (pinweaver_eal_safe_memcmp(root, log.entries[x].root, PW_HASH_SIZE))
		return PW_ERR_PATH_AUTH_FAILED;

	ret = pinweaver_eal_memcpy_s(&response->unimported_leaf_data,
				     sizeof(wrapped_leaf_data),
				     &wrapped_leaf_data,
				     sizeof(wrapped_leaf_data));
	if (ret != EC_SUCCESS)
		return PW_ERR_INTERNAL_FAILURE;

	*response_size = sizeof(*response) + PW_LEAF_PAYLOAD_SIZE;

	return EC_SUCCESS;
}

static int pw_handle_sys_info(pw_response_sys_info_t *response,
				uint16_t *response_size)
{
	update_timestamp(&response->current_ts);
	*response_size = sizeof(*response);
	return EC_SUCCESS;
}

static int pw_handle_generate_pk(struct merkle_tree_t *merkle_tree,
				const pw_request_generate_ba_pk_t *request,
				uint16_t req_size,
				pw_response_generate_ba_pk_t *response,
				uint16_t *response_size)
{
	int ret;
	uint8_t auth_channel;
	struct pw_ba_pk_t pk;
	uint8_t secret[PW_SECRET_SIZE];
	size_t secret_size = PW_SECRET_SIZE;
	struct pw_ba_ecc_pt_t server_pt;
	pinweaver_eal_sha256_ctx_t sha;

	if (req_size != sizeof(*request))
		return PW_ERR_LENGTH_INVALID;
	auth_channel = request->auth_channel;

	/* Currently we only support v0 public key format. */
	if (request->client_pbk.version != 0) {
		return PW_ERR_BIO_AUTH_PUBLIC_KEY_VERSION_MISMATCH;
	}

	if (auth_channel >= PW_BA_PK_ENTRY_COUNT) {
		return PW_ERR_BIO_AUTH_CHANNEL_INVALID;
	}

	/* Pk can only be generated on the specified auth_channel slot
	 * if no Pk is established yet and it's not blocked.
	 */
	ret = pinweaver_eal_storage_get_ba_pk(auth_channel, &pk);
	if (ret == EC_SUCCESS)
		return PW_ERR_BIO_AUTH_PK_ALREADY_ESTABLISHED;
	else if (ret != PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED)
		return PW_ERR_INTERNAL_FAILURE;

	if (generate_ba_pk_blocked) {
		return PW_ERR_BIO_AUTH_ACCESS_DENIED;
	}

	/* Perform ECDH to derive the shared secret. */
	ret = pinweaver_eal_ecdh_derive(&request->client_pbk.pt,
				secret, &secret_size, &server_pt);
	if (ret != EC_SUCCESS)
		return ret;
	if (secret_size != PW_SECRET_SIZE)
		return PW_ERR_INTERNAL_FAILURE;
	response->server_pbk.version = 0;
	pinweaver_eal_memcpy_s(&response->server_pbk.pt,
				sizeof(server_pt), &server_pt, sizeof(server_pt));

	/* sha256 the shared secret into Pk. */
	if (pinweaver_eal_sha256_init(&sha)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_update(&sha, secret, secret_size)) {
		pinweaver_eal_sha256_final(&sha, pk.key);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_final(&sha, pk.key))
		return PW_ERR_CRYPTO_FAILURE;

	/* Persist the Pk. */
	ret = pinweaver_eal_storage_set_ba_pk(auth_channel, &pk);
	if (ret != EC_SUCCESS)
		return ret;

	*response_size = sizeof(*response);
	return EC_SUCCESS;
}

static int calculate_session_key(const uint8_t client_nonce[PW_SECRET_SIZE],
				const uint8_t server_nonce[PW_SECRET_SIZE],
				const struct pw_ba_pk_t *pk,
				uint8_t session_key[PW_SECRET_SIZE])
{
	pinweaver_eal_sha256_ctx_t sha;

	/* Session key = hash(client_nonce, server_nonce, Pk) */
	if (pinweaver_eal_sha256_init(&sha)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_update(&sha, client_nonce, PW_SECRET_SIZE)) {
		pinweaver_eal_sha256_final(&sha, session_key);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_update(&sha, server_nonce, PW_SECRET_SIZE)) {
		pinweaver_eal_sha256_final(&sha, session_key);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_update(&sha, pk->key, PW_SECRET_SIZE)) {
		pinweaver_eal_sha256_final(&sha, session_key);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_sha256_final(&sha, session_key))
		return PW_ERR_CRYPTO_FAILURE;

	return EC_SUCCESS;
}

static int pw_handle_start_bio_auth(struct merkle_tree_t *merkle_tree,
				pw_request_start_bio_auth_t *request,
				uint16_t req_size,
				pw_response_start_bio_auth_t *response,
				uint16_t *response_size)
{
	int ret;
	uint8_t auth_channel;
	uint8_t *low_entropy_secret, *client_nonce;
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	uint8_t session_key[PW_SECRET_SIZE], server_nonce[PW_SECRET_SIZE];
	struct pw_ba_pk_t pk;
	pinweaver_eal_hmac_sha256_ctx_t hmac;
	size_t source_offset, dest_offset;
	uint16_t source_size;
	/* We share the response buffer to prevent allocating extra space. */
	pw_response_try_auth_t * const try_auth_response =
		(pw_response_try_auth_t *)response;

	/* We leave the h_aux length validation to pw_handle_try_auth. */
	if (req_size < sizeof(*request))
		return PW_ERR_LENGTH_INVALID;
	auth_channel = request->auth_channel;
	client_nonce = request->client_nonce;
	low_entropy_secret = request->uninit_request.low_entropy_secret;

	if (auth_channel >= PW_BA_PK_ENTRY_COUNT) {
		return PW_ERR_BIO_AUTH_CHANNEL_INVALID;
	}

	/* An established Pk on the specified auth channel is required
	 * to authenticate a rate-limiter.
	 */
	ret = pinweaver_eal_storage_get_ba_pk(auth_channel, &pk);
	if (ret != EC_SUCCESS)
		return ret;

	/* hmac-sha256 Pk and label into LEC. */
	if (pinweaver_eal_hmac_sha256_init(&hmac, merkle_tree->hmac_key,
				sizeof(merkle_tree->hmac_key))) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_update(&hmac, pk.key, PW_SECRET_SIZE)) {
		pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_update(&hmac, &auth_channel,
				sizeof(auth_channel))) {
		pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret);
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_hmac_sha256_final(&hmac, low_entropy_secret))
		return PW_ERR_CRYPTO_FAILURE;

	/* Perform nonce exchange to generate session key. */
	if (pinweaver_eal_rand_bytes(server_nonce, PW_SECRET_SIZE))
		return PW_ERR_CRYPTO_FAILURE;
	calculate_session_key(client_nonce, server_nonce, &pk, session_key);

	/* Handle try_auth return codes.
	 * Note that we should limit the errors that could happen after
	 * performing try_auth because the merkle tree root is already
	 * updated, and we want to make sure the client gets the suitable
	 * error codes if unimported_leaf_data is provided in the response.
	 * Therefore, we only allow unexpected errors (internal and crypto errors)
	 * starting from this point.
	 */
	ret = pw_handle_try_auth(
		merkle_tree,
		&request->uninit_request,
		req_size - offsetof(pw_request_start_bio_auth_t, uninit_request),
		try_auth_response,
		response_size);
	switch (ret) {
		case PW_ERR_SUCCESS_WITH_INCREMENT:
		case PW_ERR_LOWENT_AUTH_FAILED: {
			/* We need HEC later, and the response might be overwritten
			 * before we use it, so copy it first.
			 */
			if (pinweaver_eal_memcpy_s(
					high_entropy_secret,
					PW_SECRET_SIZE,
					try_auth_response->high_entropy_secret,
					PW_SECRET_SIZE)) {
				return PW_ERR_INTERNAL_FAILURE;
			}

			/* Move the unimported leaf data to the correct position. */
			source_offset = offsetof(pw_response_try_auth_t, unimported_leaf_data);
			dest_offset =
					offsetof(pw_response_start_bio_auth_t, unimported_leaf_data);
			source_size = *response_size - source_offset;
			*response_size = dest_offset + source_size;
			memmove(&response->unimported_leaf_data,
				&try_auth_response->unimported_leaf_data,
				source_size);
			if (ret == PW_ERR_LOWENT_AUTH_FAILED)
				return PW_ERR_LOWENT_AUTH_FAILED;
			break;
		}
		/* The return code shouldn't be EC_SUCCESS when doing try_auth
		 * for a biometrics leaf.
		 */
		case EC_SUCCESS: {
			return PW_ERR_INTERNAL_FAILURE;
		}
		/* Other error codes have no valid fields in the response. */
		default: {
			*response_size = 0;
			return ret;
		}
	}

	/* Encrypt the HEC using session key, and fill in other response fields. */
	if (pinweaver_eal_rand_bytes(response->iv, sizeof(response->iv)))
		return PW_ERR_CRYPTO_FAILURE;
	if (pinweaver_eal_aes256_ctr_custom(session_key,
				PW_SECRET_SIZE,
				response->iv,
				high_entropy_secret,
				PW_SECRET_SIZE,
				response->encrypted_high_entropy_secret)) {
		return PW_ERR_CRYPTO_FAILURE;
	}
	if (pinweaver_eal_memcpy_s(
				response->server_nonce,
				PW_SECRET_SIZE,
				server_nonce,
				PW_SECRET_SIZE)) {
		return PW_ERR_INTERNAL_FAILURE;
	}

	return EC_SUCCESS;
}

static int pw_handle_block_generate_ba_pk(void)
{
	generate_ba_pk_blocked = 1;
	return EC_SUCCESS;
}

struct merkle_tree_t pw_merkle_tree;

/******************************************************************************/
/* Non-static functions.
 */

void pinweaver_init(void)
{
	load_merkle_tree(&pw_merkle_tree);
	generate_ba_pk_blocked = 0;
}

int get_path_auxiliary_hash_count(const struct merkle_tree_t *merkle_tree)
{
	return ((1 << merkle_tree->bits_per_level.v) - 1) *
			merkle_tree->height.v;
}

/* Computes the SHA256 parent hash of a set of child hashes given num_hashes
 * sibling hashes in hashes[] and the index of child_hash.
 *
 * Assumptions:
 * num_hashes == fan_out - 1
 * ARRAY_SIZE(hashes) == num_hashes
 * 0 <= location <= num_hashes
 */
int compute_hash(const uint8_t hashes[][PW_HASH_SIZE], uint16_t num_hashes,
		 struct index_t location,
		 const uint8_t child_hash[PW_HASH_SIZE],
		 uint8_t result[PW_HASH_SIZE])
{
	int ret;
	pinweaver_eal_sha256_ctx_t ctx;

	ret = pinweaver_eal_sha256_init(&ctx);
	if (ret)
		return ret;
	if (location.v > 0) {
		ret = pinweaver_eal_sha256_update(&ctx, hashes[0],
						  PW_HASH_SIZE * location.v);
		if (ret) {
			pinweaver_eal_sha256_final(&ctx, result);
			return ret;
		}
	}
	ret = pinweaver_eal_sha256_update(&ctx, child_hash, PW_HASH_SIZE);
	if (ret) {
		pinweaver_eal_sha256_final(&ctx, result);
		return ret;
	}
	if (location.v < num_hashes) {
		ret = pinweaver_eal_sha256_update(
			&ctx, hashes[location.v],
			PW_HASH_SIZE * (num_hashes - location.v));
		if (ret) {
			pinweaver_eal_sha256_final(&ctx, result);
			return ret;
		}
	}
	return pinweaver_eal_sha256_final(&ctx, result);
}

/* If a request from older protocol comes, this method should make it
 * compatible with the current request structure.
 */
int make_compatible_request(struct merkle_tree_t *merkle_tree,
			    struct pw_request_t *request)
{
	switch (request->header.version) {
	case 0:
		/* The switch from protocol version 0 to 1 means all the
		 * requests have the same format, except insert_leaf.
		 * Update the request in that case.
		 */
		if (request->header.type.v == PW_INSERT_LEAF) {
			unsigned char *src = (unsigned char *)
				(&request->data.insert_leaf00.path_hashes);
			unsigned char *dest = (unsigned char *)
				(&request->data.insert_leaf01.path_hashes);
			const uint16_t src_size =
				request->header.data_length -
				offsetof(struct pw_request_insert_leaf00_t,
					 path_hashes);
			if (offsetof(struct pw_request_insert_leaf01_t,
				     path_hashes) + src_size >
			    PW_MAX_MESSAGE_SIZE) {
				/* The total length of request overflowed. */
				return 0;
			}
			memmove(dest, src, src_size);
			memset(&request->data.insert_leaf01.valid_pcr_criteria, 0,
			       PW_VALID_PCR_CRITERIA_SIZE);
			request->header.data_length +=
				PW_VALID_PCR_CRITERIA_SIZE;
		}
		/* Fallthrough to make compatible from next version */
		__attribute__((fallthrough));
	case 1:
		/* The switch from protocol version 1 to 2 means all the
		 * requests have the same format, except insert_leaf and
		 * reset_auth.
		 * Update the request in that case.
		 */
		if (request->header.type.v == PW_INSERT_LEAF) {
			unsigned char *src = (unsigned char *)
				(&request->data.insert_leaf01.path_hashes);
			unsigned char *dest = (unsigned char *)
				(&request->data.insert_leaf.path_hashes);
			const size_t src_offset = offsetof(struct pw_request_insert_leaf01_t,
					 path_hashes);
			const size_t dest_offset = offsetof(struct pw_request_insert_leaf02_t,
					 path_hashes);
			const uint16_t src_size = request->header.data_length - src_offset;
			if (dest_offset + src_size > PW_MAX_MESSAGE_SIZE) {
				/* The total length of request overflowed. */
				return 0;
			}
			memmove(dest, src, src_size);
			request->data.insert_leaf.expiration_delay_s.v = 0;
			request->data.insert_leaf.leaf_type.v = PW_LEAF_TYPE_NORMAL;
			request->header.data_length += dest_offset - src_offset;
		} else if (request->header.type.v == PW_RESET_AUTH) {
			unsigned char *src = (unsigned char *)
				(&request->data.reset_auth00.unimported_leaf_data);
			unsigned char *dest = (unsigned char *)
				(&request->data.reset_auth.unimported_leaf_data);
			const uint16_t src_size =
				request->header.data_length -
				offsetof(struct pw_request_reset_auth00_t,
					 unimported_leaf_data);
			if (offsetof(struct pw_request_reset_auth02_t,
				     unimported_leaf_data) + src_size >
			    PW_MAX_MESSAGE_SIZE) {
				/* The total length of request overflowed. */
				return 0;
			}
			memmove(dest, src, src_size);
			request->data.reset_auth.strong_reset = 0;
			request->header.data_length += 1;
		}
		/* Fallthrough to make compatible from next version */
		__attribute__((fallthrough));
	case PW_PROTOCOL_VERSION:
		return 1;
	}
	/* Unsupported version. */
	return 0;
}

/* Converts the response to be understandable by an older protocol.
 */
void make_compatible_response(int version, int req_type,
			      struct pw_response_t *response)
{
	size_t offset;

	if (version >= PW_PROTOCOL_VERSION)
		return;

	response->header.version = version;
	if (version == 0) {
		if (req_type == PW_TRY_AUTH) {
			unsigned char *src = (unsigned char *)
			    (&response->data.try_auth.unimported_leaf_data);
			unsigned char *dest = (unsigned char *)
			    (&response->data.try_auth00.unimported_leaf_data);
			memmove(dest, src,
				PW_LEAF_PAYLOAD_SIZE +
				sizeof(struct unimported_leaf_data_t));
			response->header.data_length -= PW_SECRET_SIZE;
		}
	}

	if (version <= 1) {
		if (req_type == PW_GET_LOG) {
			for (offset = 0;
				   offset + sizeof(struct pw_get_log_entry_t) <=
				   response->header.data_length;
				   offset += sizeof(struct pw_get_log_entry_t)) {
				struct pw_get_log_entry_t * entry =
					(struct pw_get_log_entry_t *) (response->data.get_log + offset);
				/* LOG_PW_TRY_AUTH00's union variant is the prefix of
				 * LOG_PW_TRY_AUTH's, so we can just change the type here.
				 */
				if (entry->type.v == LOG_PW_TRY_AUTH)
					entry->type.v = LOG_PW_TRY_AUTH00;
			}
		} else if (req_type == PW_RESET_AUTH) {
			unsigned char *src = (unsigned char *)
			    (&response->data.reset_auth02.unimported_leaf_data);
			unsigned char *dest = (unsigned char *)
			    (&response->data.reset_auth00.unimported_leaf_data);
			memmove(dest, src,
				PW_LEAF_PAYLOAD_SIZE +
				sizeof(struct unimported_leaf_data_t));
			/* clients from protocol version <= 1 won't be able to retrieve
			 * the HEC from reset_auth anymore, they can parse the response
			 * with same structure but need to deal with the logical change
			 * themselves.
			 */
			memset(response->data.reset_auth00.high_entropy_secret, 0,
			  PW_SECRET_SIZE);
			response->header.data_length += PW_SECRET_SIZE;
		}
	}
}

enum pinweaver_command_res_t pinweaver_command(void *request_buf,
					       size_t request_size,
					       void *response_buf,
					       size_t *response_size) {
	struct pw_request_t *request = request_buf;
	struct pw_response_t *response = response_buf;

	if (request_size < sizeof(request->header)) {
		PINWEAVER_EAL_INFO(
			"PinWeaver: message smaller than a header (%zd).\n",
			request_size);
		return PW_CMD_RES_TOO_SMALL;
	}

	if (request_size != request->header.data_length +
			    sizeof(request->header)) {
		PINWEAVER_EAL_INFO(
			"PinWeaver: header size mismatch %zd != %zd.\n",
			request_size,
			request->header.data_length + sizeof(request->header));
		return PW_CMD_RES_SIZE;
	}

	/* The response_size is validated by compile time checks. */

	/* The return value of this function call is intentionally unused. */
	pw_handle_request(&pw_merkle_tree, request, response);

	*response_size = response->header.data_length +
			 sizeof(response->header);

	/* The response is only sent for EC_SUCCESS so it is used even for
	 * errors which are reported through header.return_code.
	 */
	return PW_CMD_RES_SUCCESS;
}


/* Handles the message in request using the context in merkle_tree and writes
 * the results to response. The return value captures any error conditions that
 * occurred or EC_SUCCESS if there were no errors.
 *
 * This implementation is written to handle the case where request and response
 * exist at the same memory location---are backed by the same buffer. This means
 * the implementation requires that no reads are made to request after response
 * has been written to.
 */
int pw_handle_request(struct merkle_tree_t *merkle_tree,
		      struct pw_request_t *request,
		      struct pw_response_t *response)
{
	int32_t ret;
	uint16_t resp_length;
	/* Store the message type of the request since it may be overwritten
	 * inside the switch whenever response and request overlap in memory.
	 */
	struct pw_message_type_t type = request->header.type;
	int version = request->header.version;

	resp_length = 0;

	if (!make_compatible_request(merkle_tree, request)) {
		ret = PW_ERR_VERSION_MISMATCH;
		goto cleanup;
	}
	switch (type.v) {
	case PW_RESET_TREE:
		ret = pw_handle_reset_tree(merkle_tree,
					   &request->data.reset_tree,
					   request->header.data_length);
		break;
	case PW_INSERT_LEAF:
		ret = pw_handle_insert_leaf(merkle_tree,
					    &request->data.insert_leaf,
					    request->header.data_length,
					    &response->data.insert_leaf,
					    &resp_length);
		break;
	case PW_REMOVE_LEAF:
		ret = pw_handle_remove_leaf(merkle_tree,
					    &request->data.remove_leaf,
					    request->header.data_length);
		break;
	case PW_TRY_AUTH:
		ret = pw_handle_try_auth(merkle_tree, &request->data.try_auth,
					 request->header.data_length,
					 &response->data.try_auth,
					 &resp_length);
		break;
	case PW_RESET_AUTH:
		ret = pw_handle_reset_auth(merkle_tree,
					   &request->data.reset_auth,
					   request->header.data_length,
					   &response->data.reset_auth,
					   &resp_length);
		break;
	case PW_GET_LOG:
		ret = pw_handle_get_log(merkle_tree, &request->data.get_log,
					request->header.data_length,
					(void *)&response->data, &resp_length);
		break;
	case PW_LOG_REPLAY:
		ret = pw_handle_log_replay(merkle_tree,
					   &request->data.log_replay,
					   request->header.data_length,
					   &response->data.log_replay,
					   &resp_length);
		break;
	case PW_SYS_INFO:
		ret = pw_handle_sys_info(&response->data.sys_info, &resp_length);
		break;
	case PW_GENERATE_BA_PK:
		ret = pw_handle_generate_pk(merkle_tree,
					&request->data.generate_pk,
					request->header.data_length,
					&response->data.generate_pk,
					&resp_length);
		break;
	case PW_START_BIO_AUTH:
		ret = pw_handle_start_bio_auth(merkle_tree,
					&request->data.start_bio_auth,
					request->header.data_length,
					&response->data.start_bio_auth,
					&resp_length);
		break;
	case PW_BLOCK_GENERATE_BA_PK:
		ret = pw_handle_block_generate_ba_pk();
		break;
	default:
		ret = PW_ERR_TYPE_INVALID;
		break;
	}
cleanup:
	response->header.version = PW_PROTOCOL_VERSION;
	response->header.data_length = resp_length;
	response->header.result_code = ret;
	if (pinweaver_eal_memcpy_s(&response->header.root,
				   sizeof(response->header.root),
				   merkle_tree->root,
				   sizeof(merkle_tree->root))) {
		ret = PW_ERR_INTERNAL_FAILURE;
	}

	make_compatible_response(version, type.v, response);

	return ret;
};
