//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Lightweight tftp daemon
//-----------------------------------------------------------------------------------------
// This file is part of 'boot-it'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'boot-it', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//-----------------------------------------------------------------------------------------
#pragma once

#include <stdint.h>
#include <limits.h>
#include <vector>
#include <string>

typedef struct tftpd_opts
{
  uint16_t port;
  char addr[32];
  int uparms; /* Use the current user's perms to determine if a file is
                 accessible, instead of requiring O+RW */

  std::vector<std::string> paths; /* list of search paths */
} tftpd_opts_t;

typedef struct tftpd_ctx tftpd_ctx_t;

tftpd_ctx_t* tftpd_start(const tftpd_opts_t *opts);
void tftpd_stop(tftpd_ctx_t* ctx);
int tftpd(const tftpd_opts_t *opts);
