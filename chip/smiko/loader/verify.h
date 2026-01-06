/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __EC_CHIP_G_LOADER_VERIFY_H
#define __EC_CHIP_G_LOADER_VERIFY_H

/* Verify a header has one of the hardcoded Key IDs. we can expect. */
uint32_t is_good_key(const uint32_t *keyid_ptr);

int is_dev_signed(int keyid); // TODO: Deprecate this

/* Check if the target uses a production or dev key ID. */
int is_prod_signed(uint32_t keyid);

/*
 * Verify a RSA PKCS1.5 signature against an expected sha256. Unlocks for
 * execution upon success.
 */
void LOADERKEY_verify(const uint32_t *key,
		      const uint32_t *signature, const uint32_t *sha256);

#endif  /* __EC_CHIP_G_LOADER_VERIFY_H */
