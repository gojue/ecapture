// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ECAPTURE_OPENSSL_UNTAG_H
#define ECAPTURE_OPENSSL_UNTAG_H

#include "ecapture.h"

#define OPENSSL_USER_POINTER_MASK 0x00FFFFFFFFFFFFFFULL

static __always_inline void *openssl_untag_user_pointer(const void *pointer) {
    return (void *)((u64)pointer & OPENSSL_USER_POINTER_MASK);
}

static __always_inline long openssl_probe_read_user(void *dst, u32 size, const void *src) {
    return bpf_probe_read_user(dst, size, openssl_untag_user_pointer(src));
}

#endif
