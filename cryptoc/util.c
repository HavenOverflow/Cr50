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
#include "cryptoc/util.h"

static void always_memset_impl(volatile char *s, int c, size_t n) {
  while (n--)
    *s++ = c;
}

void *always_memset(void *s, int c, size_t n) {
  always_memset_impl((char*) s, c, n);
  return s;
}

int ct_memeq(const void* s1, const void* s2, size_t n) {
  volatile uint8_t diff = 0;
  const uint8_t* ps1 = s1;
  const uint8_t* ps2 = s2;

  while (n--) {
    diff |= *ps1 ^ *ps2;
    ps1++;
    ps2++;
  }

  // Counter-intuitive, but we can't just return diff because we don't want to
  // leak the xor of non-equal bytes
  return 0 != diff;
}
