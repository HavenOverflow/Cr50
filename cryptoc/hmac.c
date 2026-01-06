// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "cryptoc/hmac.h"
#include "cryptoc/util.h"

#include <string.h>
#include "cryptoc/sha.h"
#include "cryptoc/md5.h"
#include "cryptoc/sha224.h"
#include "cryptoc/sha256.h"
#include "cryptoc/sha384.h"
#include "cryptoc/sha512.h"

static void HMAC_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  unsigned int i;
  memset(&ctx->opad[0], 0, sizeof(ctx->opad));

  if (len > HASH_block_size(&ctx->hash)) {
    HASH_init(&ctx->hash);
    HASH_update(&ctx->hash, key, len);
    memcpy(&ctx->opad[0], HASH_final(&ctx->hash), HASH_size(&ctx->hash));
  } else {
    memcpy(&ctx->opad[0], key, len);
  }

  for (i = 0; i < HASH_block_size(&ctx->hash); ++i) {
    ctx->opad[i] ^= 0x36;
  }

  HASH_init(&ctx->hash);
  HASH_update(&ctx->hash, ctx->opad, HASH_block_size(&ctx->hash));  // hash ipad

  for (i = 0; i < HASH_block_size(&ctx->hash); ++i) {
    ctx->opad[i] ^= (0x36 ^ 0x5c);
  }
}

void HMAC_MD5_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  MD5_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}

void HMAC_SHA_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  SHA_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}

void HMAC_SHA224_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  SHA224_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}

void HMAC_SHA256_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  SHA256_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}

#ifdef SHA512_SUPPORT
void HMAC_SHA384_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  SHA384_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}

void HMAC_SHA512_init(LITE_HMAC_CTX* ctx, const void* key, unsigned int len) {
  SHA512_init(&ctx->hash);
  HMAC_init(ctx, key, len);
}
#endif

const uint8_t* HMAC_final(LITE_HMAC_CTX* ctx) {
#ifndef SHA512_SUPPORT
  uint8_t digest[32];  // upto SHA2-256
#else
  uint8_t digest[64];  // upto SHA2-512
#endif
  memcpy(digest, HASH_final(&ctx->hash),
         (HASH_size(&ctx->hash) <= sizeof(digest) ?
             HASH_size(&ctx->hash) : sizeof(digest)));
  HASH_init(&ctx->hash);
  HASH_update(&ctx->hash, ctx->opad, HASH_block_size(&ctx->hash));
  HASH_update(&ctx->hash, digest, HASH_size(&ctx->hash));
  always_memset(&ctx->opad[0], 0, sizeof(ctx->opad));  // wipe key
  return HASH_final(&ctx->hash);
}
