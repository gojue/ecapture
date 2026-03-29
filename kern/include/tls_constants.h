// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Shared TLS constants used by OpenSSL / BoringSSL / GnuTLS masterkey probes.

#pragma once

/* TLS random and secret sizes */
#define SSL3_RANDOM_SIZE 32
#define MASTER_SECRET_MAX_LEN 48
#define EVP_MAX_MD_SIZE 64

/* TLS version numbers (RFC 8446) */
#define TLS1_1_VERSION 0x0302
#define TLS1_2_VERSION 0x0303
#define TLS1_3_VERSION 0x0304

