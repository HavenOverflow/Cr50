
/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef __PINWEAVER_EAL_TYPES_H
#define __PINWEAVER_EAL_TYPES_H

#include <console.h>
#include <dcrypto.h>
#include <compile_time_macros.h>

typedef struct sha256_ctx pinweaver_eal_sha256_ctx_t;
typedef struct hmac_sha256_ctx pinweaver_eal_hmac_sha256_ctx_t;

#define RESTART_TIMER_THRESHOLD (10 /* seconds */)

#define PINWEAVER_EAL_INFO(...) cprints(CC_TASK, __VA_ARGS__)

/* Key names for nvmem_vars */
#define PW_TREE_VAR "pwT0"
#define PW_LOG_VAR0 "pwL0"
#define PW_FP_PK "pwP0"

#define PW_FP_AUTH_CHANNEL 0

#endif  /* __PINWEAVER_EAL_TYPES_H */
