/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* Shared types between Cr50 and the AP side code. */

#ifndef __PINWEAVER_PINWEAVER_TYPES_H
#define __PINWEAVER_PINWEAVER_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PW_PACKED __packed

#define PW_PROTOCOL_VERSION 2
#define PW_LEAF_MAJOR_VERSION 0
/* The change from version zero to one is the addition of valid_pcr_value
 * metadata. The change from version one to two is the addition of the
 * expiration timestamp.
 */
#define PW_LEAF_MINOR_VERSION 2

#define PW_MAX_MESSAGE_SIZE (2048 - 12 /* sizeof(struct tpm_cmd_header) */)

/* The block size of encryption used for wrapped_leaf_data_t. */
#define PW_WRAP_BLOCK_SIZE 16

#define PW_ALIGN_TO_WRD __aligned(4)

#define PW_ALIGN_TO_BLK __aligned(PW_WRAP_BLOCK_SIZE)

#define PW_BA_ECC_CORD_SIZE 32

#define PW_BA_PK_ENTRY_COUNT 2

#define PW_HMAC_IV_SIZE_V1 4
#define PW_HMAC_IV_SIZE_V2 PW_WRAP_BLOCK_SIZE

enum pw_error_codes_enum {
	PW_ERR_VERSION_MISMATCH = 0x10000, /* EC_ERROR_INTERNAL_FIRST */
	PW_ERR_TREE_INVALID,
	PW_ERR_LENGTH_INVALID,
	PW_ERR_TYPE_INVALID,
	PW_ERR_BITS_PER_LEVEL_INVALID,
	PW_ERR_HEIGHT_INVALID,
	PW_ERR_LABEL_INVALID,
	PW_ERR_DELAY_SCHEDULE_INVALID,
	PW_ERR_PATH_AUTH_FAILED,
	PW_ERR_LEAF_VERSION_MISMATCH,
	PW_ERR_HMAC_AUTH_FAILED,
	PW_ERR_LOWENT_AUTH_FAILED,
	PW_ERR_RESET_AUTH_FAILED,
	PW_ERR_CRYPTO_FAILURE,
	PW_ERR_RATE_LIMIT_REACHED,
	PW_ERR_ROOT_NOT_FOUND,
	PW_ERR_NV_EMPTY,
	PW_ERR_NV_LENGTH_MISMATCH,
	PW_ERR_NV_VERSION_MISMATCH,
	PW_ERR_PCR_NOT_MATCH,
	PW_ERR_INTERNAL_FAILURE,
	PW_ERR_EXPIRED,
	PW_ERR_BIO_AUTH_CHANNEL_INVALID,
	PW_ERR_BIO_AUTH_PUBLIC_KEY_VERSION_MISMATCH,
	PW_ERR_BIO_AUTH_ACCESS_DENIED,
	PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED,
	/* Log replay depends on the return code to decide whether the attempt
	 * counter should be increased, but try_auth on a biometrics leaf should
	 * always increase the counter. Therefore, use this special error code
	 * when logging a try_auth event like this.
	 */
	PW_ERR_SUCCESS_WITH_INCREMENT,
	PW_ERR_BIO_AUTH_PK_ALREADY_ESTABLISHED,
};

/* Represents the log2(fan out) of a tree. */
struct PW_PACKED bits_per_level_t {
	uint8_t v;
};

/* Represent the height of a tree. */
struct PW_PACKED height_t {
	uint8_t v;
};

/* Represents a child index of a node in a tree. */
struct PW_PACKED index_t {
	uint8_t v;
};

/* Represents the child index for each level of a tree along a path to a leaf.
 * It is a Little-endian unsigned integer with the following value (MSB->LSB)
 * | Zero padding | 1st level index | ... | leaf index |,
 * where each index is represented by bits_per_level bits.
 */
struct PW_PACKED label_t {
	uint64_t v;
};

/* Represents a count of failed login attempts. This is capped at UINT32_MAX. */
struct PW_PACKED attempt_count_t {
	uint32_t v;
};

/* Represents a notion of time. */
struct PW_PACKED pw_timestamp_t {
	/* Number of boots. This is used to track if Cr50 has rebooted since
	 * timer_value was recorded.
	 */
	uint32_t boot_count;
	/* Seconds since boot. */
	uint64_t timer_value;
};

/* Represents a time interval in seconds.
 *
 * This only needs to be sufficiently large to represent the longest time
 * between allowed attempts.
 */
struct PW_PACKED time_diff_t {
	uint32_t v;
};
#define PW_BLOCK_ATTEMPTS UINT32_MAX

/* Number of bytes required for a hash or hmac value in the merkle tree. */
#define PW_HASH_SIZE 32

/* Represents a single entry in a delay schedule table. */
struct PW_PACKED delay_schedule_entry_t {
	struct attempt_count_t attempt_count;
	struct time_diff_t time_diff;
};

/* Represents a set of PCR values hashed into a single digest. This is a
 * criterion that can be added to a leaf. A leaf is valid only if at least one
 * of the valid_pcr_value_t criteria it contains is satisfied.
 */
struct PW_PACKED valid_pcr_value_t {
	/* The set of PCR indexes that have to pass the validation. */
	uint8_t bitmask[2];
	/* The hash digest of the PCR values contained in the bitmask */
	uint8_t digest[32];
};

/* Represents the number of entries in the delay schedule table which can be
 * used to determine the next time an authentication attempt can be made.
 */
#define PW_SCHED_COUNT 16

/* Represents the maximum number of criteria for valid PCR values.
 */
#define PW_MAX_PCR_CRITERIA_COUNT 2

/* Number of bytes required to store a secret.
 */
#define PW_SECRET_SIZE 32

enum pw_leaf_type_enum {
	PW_LEAF_TYPE_NORMAL,
	PW_LEAF_TYPE_BIOMETRICS,
};

struct PW_PACKED pw_leaf_type_t {
	uint8_t v;
};

struct PW_PACKED leaf_version_t {
	/* minor comes first so this struct will be compatibile with uint32_t
	 * comparisons for little endian to make version comparisons easier.
	 *
	 * Changes to minor versions are allowed to add new fields, but not
	 * remove existing fields, and they are allowed to be interpreted by
	 * previous versions---any extra fields are truncated.
	 *
	 * Leafs will reject future major versions assuming they are
	 * incompatible, so fields in struct leaf_public_data_t and
	 * struct leaf_sensitive_data_t may be removed for new major versions.
	 * Upgrades across major versions will require explicit logic to
	 * map the old struct to the new struct or vice versa.
	 */
	uint16_t minor;
	uint16_t major;
};

/* Do not change this within the same PW_LEAF_MAJOR_VERSION. */
struct PW_PACKED leaf_header_t {
	/* Always have leaf_version at the beginning of
	 * struct wrapped_leaf_data_t to maintain preditable behavior across
	 * versions.
	 */
	struct leaf_version_t leaf_version;
	uint16_t pub_len;
	uint16_t sec_len;
};

/* Do not remove fields within the same PW_LEAF_MAJOR_VERSION. */
/* Unencrypted part of the leaf data.
 */
struct PW_PACKED leaf_public_data_t {
	struct label_t label;
	struct delay_schedule_entry_t delay_schedule[PW_SCHED_COUNT];

	/* State used to rate limit. */
	struct pw_timestamp_t last_access_ts;
	struct attempt_count_t attempt_count;
	struct valid_pcr_value_t valid_pcr_criteria[PW_MAX_PCR_CRITERIA_COUNT];

	/* Timestamp when the leaf data expires.	*/
	struct pw_timestamp_t expiration_ts;
	/* Used to update expiration_ts after reset leaf */
	struct time_diff_t expiration_delay_s;
	struct pw_leaf_type_t leaf_type;
};

/* Represents a struct of unknown length to be imported to process a request. */
struct PW_PACKED unimported_leaf_data_t {
	/* This is first so that head.leaf_version will be the first field
	 * in the struct to make handling different struct versions easier.
	 */
	struct leaf_header_t head;
	/* Covers .head, .iv, and .payload (excluding path_hashes) */
	uint8_t hmac[PW_HASH_SIZE];
	uint8_t iv[PW_WRAP_BLOCK_SIZE];
	/* This field is treated as having a zero size by the compiler so the
	 * actual size needs to be added to the size of this struct. This allows
	 * for forward compatibility using the pub_len and sec_len fields in the
	 * header.
	 *
	 * Has following layout:
	 * Required:
	 *  uint8_t pub_data[head.pub_len];
	 *  uint8_t ciphter_text[head.sec_len];
	 *
	 * For Requests only:
	 *  uint8_t path_hashes[get_path_auxiliary_hash_count(.)][PW_HASH_SIZE];
	 */
	uint8_t payload[];
};

/* Biometrics specific types. */

struct PW_PACKED pw_ba_pk_t {
	uint8_t key[PW_SECRET_SIZE];
};

struct PW_PACKED pw_ba_ecc_pt_t {
	uint8_t x[PW_BA_ECC_CORD_SIZE];
	uint8_t y[PW_BA_ECC_CORD_SIZE];
};

struct PW_PACKED pw_ba_pbk_t {
	uint8_t version;
	struct pw_ba_ecc_pt_t pt;
};

/******************************************************************************/
/* Message structs
 *
 * The message format is a pw_request_header_t followed by the data
 * We don't expect to ever update the enum entry an operation maps to, so it
 * doesn't need to be versioned.
 */

enum pw_message_type_enum {
	PW_MT_INVALID = 0,

	/* Request / "Question" types. */
	PW_RESET_TREE = 1,
	PW_INSERT_LEAF = 2,
	PW_REMOVE_LEAF = 3,
	PW_TRY_AUTH = 4,
	PW_RESET_AUTH = 5,
	PW_GET_LOG = 6,
	PW_LOG_REPLAY = 7,
	PW_SYS_INFO = 8,
	/* The following are vendor specific pinweaver commands
	 * for biometrics feature.
	 */
	PW_GENERATE_BA_PK = 9,
	PW_START_BIO_AUTH = 10,
	PW_BLOCK_GENERATE_BA_PK = 11,
};

/* This enum is introduced because when we need a new variant in the log for
 * existing message types, we don't want to add a new message type in
 * pw_message_type_enum. Instead, we want to give the message_type field
 * in log entries another meaning.
 */
enum pw_log_message_type_enum {
	LOG_PW_MT_INVALID00 = 0,
	LOG_PW_RESET_TREE00 = 1,
	LOG_PW_INSERT_LEAF00 = 2,
	LOG_PW_REMOVE_LEAF00 = 3,
	/* This log format is used in protocol version <= 1. */
	LOG_PW_TRY_AUTH00 = 4,
	/* All the fields above correspond to the same kind of message with matching
	 * value in pw_message_type_enum.
	 */
	LOG_PW_TRY_AUTH02 = 5,

	LOG_PW_MT_INVALID = LOG_PW_MT_INVALID00,
	LOG_PW_RESET_TREE = LOG_PW_RESET_TREE00,
	LOG_PW_INSERT_LEAF = LOG_PW_INSERT_LEAF00,
	LOG_PW_REMOVE_LEAF = LOG_PW_REMOVE_LEAF00,
	LOG_PW_TRY_AUTH = LOG_PW_TRY_AUTH02,
};

struct PW_PACKED pw_message_type_t {
	uint8_t v;
};

struct PW_PACKED pw_request_header_t {
	uint8_t version;
	struct pw_message_type_t type;
	uint16_t data_length;
};

struct PW_PACKED pw_response_header_t {
	uint8_t version;
	uint16_t data_length; /* Does not include the header. */
	uint32_t result_code;
	uint8_t root[PW_HASH_SIZE];
};

struct PW_PACKED pw_request_reset_tree00_t {
	struct bits_per_level_t bits_per_level;
	struct height_t height;
};

typedef struct pw_request_reset_tree00_t pw_request_reset_tree_t;

/* This is only used for parsing incoming data before version 01 */
struct PW_PACKED pw_request_insert_leaf00_t {
	struct label_t label;
	struct delay_schedule_entry_t delay_schedule[PW_SCHED_COUNT];
	uint8_t low_entropy_secret[PW_SECRET_SIZE];
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	uint8_t reset_secret[PW_SECRET_SIZE];
	/* This is a variable length field because it size is determined at
	 * runtime based on the chosen tree parameters. Its size is treated as
	 * zero by the compiler so the computed size needs to be added to the
	 * size of this struct in order to determine the actual size. This field
	 * has the form:
	 * uint8_t path_hashes[get_path_auxiliary_hash_count(.)][PW_HASH_SIZE];
	 */
	uint8_t path_hashes[][PW_HASH_SIZE];
};

/* This is only used for parsing incoming data before version 02 */
struct PW_PACKED pw_request_insert_leaf01_t {
	struct label_t label;
	struct delay_schedule_entry_t delay_schedule[PW_SCHED_COUNT];
	uint8_t low_entropy_secret[PW_SECRET_SIZE];
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	uint8_t reset_secret[PW_SECRET_SIZE];
	struct valid_pcr_value_t valid_pcr_criteria[PW_MAX_PCR_CRITERIA_COUNT];
	/* This is a variable length field because it size is determined at
	 * runtime based on the chosen tree parameters. Its size is treated as
	 * zero by the compiler so the computed size needs to be added to the
	 * size of this struct in order to determine the actual size. This field
	 * has the form:
	 * uint8_t path_hashes[get_path_auxiliary_hash_count(.)][PW_HASH_SIZE];
	 */
	uint8_t path_hashes[][PW_HASH_SIZE];
};

struct PW_PACKED pw_request_insert_leaf02_t {
	struct label_t label;
	struct delay_schedule_entry_t delay_schedule[PW_SCHED_COUNT];
	uint8_t low_entropy_secret[PW_SECRET_SIZE];
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	uint8_t reset_secret[PW_SECRET_SIZE];
	struct valid_pcr_value_t valid_pcr_criteria[PW_MAX_PCR_CRITERIA_COUNT];
	/* 0 means the node will never expire. */
	struct time_diff_t expiration_delay_s;
	struct pw_leaf_type_t leaf_type;
	/* Only valid when leaf_type is BIOMETRICS. */
	uint8_t auth_channel;
	/* This is a variable length field because it size is determined at
	 * runtime based on the chosen tree parameters. Its size is treated as
	 * zero by the compiler so the computed size needs to be added to the
	 * size of this struct in order to determine the actual size. This field
	 * has the form:
	 * uint8_t path_hashes[get_path_auxiliary_hash_count(.)][PW_HASH_SIZE];
	 */
	uint8_t path_hashes[][PW_HASH_SIZE];
};

typedef struct pw_request_insert_leaf02_t pw_request_insert_leaf_t;

struct PW_PACKED pw_response_insert_leaf00_t {
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_response_insert_leaf00_t pw_response_insert_leaf_t;

struct PW_PACKED pw_request_remove_leaf00_t {
	struct label_t leaf_location;
	uint8_t leaf_hmac[PW_HASH_SIZE];
	/* See (struct pw_request_insert_leaf_t).path_hashes. */
	uint8_t path_hashes[][PW_HASH_SIZE];
};

typedef struct pw_request_remove_leaf00_t pw_request_remove_leaf_t;

struct PW_PACKED pw_request_try_auth00_t {
	uint8_t low_entropy_secret[PW_SECRET_SIZE];
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_request_try_auth00_t pw_request_try_auth_t;

/* This is only used to send response data before version 01 */
struct PW_PACKED pw_response_try_auth00_t {
	/* Valid for the PW_ERR_RATE_LIMIT_REACHED return code only. */
	struct time_diff_t seconds_to_wait;
	/* Valid for the EC_SUCCESS return code only. */
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	/* Valid for the PW_ERR_LOWENT_AUTH_FAILED and EC_SUCCESS return codes.
	 */
	struct unimported_leaf_data_t unimported_leaf_data;
};

struct PW_PACKED pw_response_try_auth01_t {
	/* Valid for the PW_ERR_RATE_LIMIT_REACHED return code only. */
	struct time_diff_t seconds_to_wait;
	/* Valid for the EC_SUCCESS return code only. */
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	/* Valid for the EC_SUCCESS return code only. */
	uint8_t reset_secret[PW_SECRET_SIZE];
	/* Valid for the PW_ERR_LOWENT_AUTH_FAILED and EC_SUCCESS return codes.
	 */
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_response_try_auth01_t pw_response_try_auth_t;

/* This is only used for parsing incoming data before version 02 */
struct PW_PACKED pw_request_reset_auth00_t {
	uint8_t reset_secret[PW_SECRET_SIZE];
	struct unimported_leaf_data_t unimported_leaf_data;
};

struct PW_PACKED pw_request_reset_auth02_t {
	uint8_t reset_secret[PW_SECRET_SIZE];
	/* If strong_reset is non-zero, the expiration timestamp will be reset too. */
	uint8_t strong_reset;
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_request_reset_auth02_t pw_request_reset_auth_t;

/* This is only used for parsing incoming data before version 02 */
struct PW_PACKED pw_response_reset_auth00_t {
	uint8_t high_entropy_secret[PW_SECRET_SIZE];
	struct unimported_leaf_data_t unimported_leaf_data;
};

struct PW_PACKED pw_response_reset_auth02_t {
	/* Starting from protocol version 2, HEC isn't returned in reset_auth. */
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_response_reset_auth02_t pw_response_reset_auth_t;

struct PW_PACKED pw_request_get_log00_t {
	/* The root on the CrOS side that needs to be brought back in sync with
	 * the root on Cr50. If this doesn't match a log entry, the entire log
	 * is returned.
	 */
	uint8_t root[PW_HASH_SIZE];
};

typedef struct pw_request_get_log00_t pw_request_get_log_t;

struct PW_PACKED pw_request_log_replay00_t {
	/* The root hash after the desired log event.
	 * The log entry that matches this hash contains all the necessary
	 * data to update wrapped_leaf_data
	 */
	uint8_t log_root[PW_HASH_SIZE];
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_request_log_replay00_t pw_request_log_replay_t;

struct PW_PACKED pw_response_log_replay00_t {
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_response_log_replay00_t pw_response_log_replay_t;

/* We expect this type definition to never change so it isn't versioned. */
struct PW_PACKED pw_get_log_entry_t {
	/* The root hash after this operation. */
	uint8_t root[PW_HASH_SIZE];
	/* The label of the leaf that was operated on. */
	struct label_t label;
	/* The type of operation. This should be one of
	 * LOG_PW_INSERT_LEAF,
	 * LOG_PW_REMOVE_LEAF,
	 * LOG_PW_TRY_AUTH (or LOG_PW_TRY_AUTH00).
	 *
	 * Successful LOG_PW_RESET_AUTH events are included
	 */
	struct pw_message_type_t type;
	/* Type specific fields. */
	union {
		/* LOG_PW_INSERT_LEAF */
		uint8_t leaf_hmac[PW_HASH_SIZE];
		/* LOG_PW_REMOVE_LEAF */
		/* LOG_PW_TRY_AUTH */
		struct PW_PACKED {
			struct pw_timestamp_t last_access_ts;
			int32_t return_code;
			/* This field is introduced in protocol version 2, we reuse the existing
			* variant but used another variant type to distinguish whether this field
			* exists.
			*/
			struct pw_timestamp_t expiration_ts;
		};
	};
};

struct PW_PACKED pw_response_sys_info02_t {
	struct pw_timestamp_t current_ts;
};

typedef struct pw_response_sys_info02_t pw_response_sys_info_t;

/* The following are vendor specific pinweaver commands for
 * the biometrics feature.
 */

struct PW_PACKED pw_request_generate_ba_pk02_t {
	uint8_t auth_channel;
	struct pw_ba_pbk_t client_pbk;
};

typedef struct pw_request_generate_ba_pk02_t pw_request_generate_ba_pk_t;

struct PW_PACKED pw_response_generate_ba_pk02_t {
	struct pw_ba_pbk_t server_pbk;
};

typedef struct pw_response_generate_ba_pk02_t pw_response_generate_ba_pk_t;

struct PW_PACKED pw_request_start_bio_auth02_t {
	uint8_t auth_channel;
	uint8_t client_nonce[PW_SECRET_SIZE];
	/* The request contains a standard try_auth request, except
	 * that the LEC field is zeroed out. The server will fill in
	 * HMAC(Pk|auth_channel) as LEC.
	 */
	struct pw_request_try_auth00_t uninit_request;
};

typedef struct pw_request_start_bio_auth02_t pw_request_start_bio_auth_t;

struct PW_PACKED pw_response_start_bio_auth02_t {
	/* The response format is quite different from a standard try_auth,
	 * so we didn't reuse it.
	 */
	/* Valid for the EC_SUCCESS return code only. */
	uint8_t server_nonce[PW_SECRET_SIZE];
	/* Valid for the EC_SUCCESS return code only. Encrypted by the session key
	 * established by client and server nonces and Pk.
	 */
	uint8_t encrypted_high_entropy_secret[PW_SECRET_SIZE];
	/* Valid for the EC_SUCCESS return code only. Used in the AES-CTR encryption.
	*/
	uint8_t iv[PW_WRAP_BLOCK_SIZE];
	/* Valid for the PW_ERR_LOWENT_AUTH_FAILED and EC_SUCCESS return codes only.
	 */
	struct unimported_leaf_data_t unimported_leaf_data;
};

typedef struct pw_response_start_bio_auth02_t pw_response_start_bio_auth_t;

struct PW_PACKED pw_request_t {
	struct pw_request_header_t header;
	union {
    /* version-stable types */
		struct pw_request_reset_tree00_t reset_tree00;
		struct pw_request_insert_leaf00_t insert_leaf00;
		struct pw_request_insert_leaf01_t insert_leaf01;
		struct pw_request_insert_leaf02_t insert_leaf02;
		struct pw_request_remove_leaf00_t remove_leaf00;
		struct pw_request_try_auth00_t try_auth00;
		struct pw_request_reset_auth00_t reset_auth00;
		struct pw_request_reset_auth02_t reset_auth02;
		struct pw_request_get_log00_t get_log00;
		struct pw_request_log_replay00_t log_replay00;
		struct pw_request_generate_ba_pk02_t generate_pk02;
		struct pw_request_start_bio_auth02_t start_bio_auth02;

		/* currently used types */
		pw_request_reset_tree_t reset_tree;
		pw_request_insert_leaf_t insert_leaf;
		pw_request_remove_leaf_t remove_leaf;
		pw_request_try_auth_t try_auth;
		pw_request_reset_auth_t reset_auth;
		pw_request_get_log_t get_log;
		pw_request_log_replay_t log_replay;
		pw_request_generate_ba_pk_t generate_pk;
		pw_request_start_bio_auth_t start_bio_auth;
	} data;
};

struct PW_PACKED pw_response_t {
	struct pw_response_header_t header;
	union {
    /* version-stable types */
		struct pw_response_insert_leaf00_t insert_leaf00;
		struct pw_response_try_auth00_t try_auth00;
		struct pw_response_try_auth01_t try_auth01;
		struct pw_response_reset_auth00_t reset_auth00;
		struct pw_response_reset_auth02_t reset_auth02;
		/* An array with as many entries as are present in the log up to
		 * the present time or will fit in the message.
		 */
		uint8_t get_log[0];
		struct pw_response_log_replay00_t log_replay00;
		struct pw_response_sys_info02_t sys_info02;
		struct pw_response_generate_ba_pk02_t generate_pk02;
		struct pw_response_start_bio_auth02_t start_bio_auth02;

		/* currently used types */
		pw_response_insert_leaf_t insert_leaf;
		pw_response_try_auth_t try_auth;
		pw_response_reset_auth_t reset_auth;
		pw_response_log_replay_t log_replay;
		pw_response_sys_info_t sys_info;
		pw_response_generate_ba_pk_t generate_pk;
		pw_response_start_bio_auth_t start_bio_auth;
	} data;
};

/* An explicit limit is set because struct unimported_leaf_data_t can have more
 * than one variable length field so the max length for these fields needs to be
 * defined so that meaningful parameter limits can be set to validate the tree
 * parameters.
 *
 * 1024 was chosen because it is 1/2 of 2048 and allows for a maximum tree
 * height of 10 for the default fan-out of 4.
 */
#define PW_MAX_PATH_SIZE 1024

#ifdef __cplusplus
}
#endif

#endif  /* __PINWEAVER_PINWEAVER_TYPES_H */
