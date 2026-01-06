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
#include "cryptoc/sha224.h"
#include "cryptoc/sha256.h"

#include <string.h>
#include <stdint.h>

static const HASH_VTAB SHA224_VTAB = {
  SHA224_init,
  SHA256_update,
  SHA256_final,
  SHA224_hash,
  SHA224_DIGEST_SIZE,
#ifdef SHA512_SUPPORT
  SHA224_BLOCK_SIZE,
#endif
};

void SHA224_init(LITE_SHA224_CTX* ctx) {
  ctx->f = &SHA224_VTAB;
  ctx->state[0] = 0xc1059ed8;
  ctx->state[1] = 0x367cd507;
  ctx->state[2] = 0x3070dd17;
  ctx->state[3] = 0xf70e5939;
  ctx->state[4] = 0xffc00b31;
  ctx->state[5] = 0x68581511;
  ctx->state[6] = 0x64f98fa7;
  ctx->state[7] = 0xbefa4fa4;
  ctx->count = 0;
}

/* Convenience function */
const uint8_t* SHA224_hash(const void* data, size_t len,
                           uint8_t* digest) {
  LITE_SHA224_CTX ctx;
  SHA224_init(&ctx);
  SHA224_update(&ctx, data, len);
  memcpy(digest, SHA224_final(&ctx), SHA224_DIGEST_SIZE);
  return digest;
}
