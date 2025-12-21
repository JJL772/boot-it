//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Boot-it main implementation
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
#include <string>
#include <list>

#include <netinet/in.h>

typedef struct bootp_device
{
  std::string mac;
  in_addr_t ip;
  std::string file;
  std::string vend;
} bootp_device_t;

typedef struct bootpd_opts
{
  std::string interface;
  std::string hostname;

  int verbose;
  
  std::list<bootp_device> devs;
  
} bootpd_opts_t;

typedef struct bootpd_ctx bootpd_ctx_t;

bootpd_ctx_t* bootpd_start(const bootpd_opts_t* opts);
void bootpd_stop(bootpd_ctx_t* c);
void bootpd_pause(bootpd_ctx_t* c, int pause);

/*-------------------- Protocol Definitions --------------------*/

#define BOOTP_SERVER_PORT 67
#define BOOTP_CLIENT_PORT 68

#define BOOTP_OP_REQUEST 1
#define BOOTP_OP_REPLY 2

struct __attribute__((packed))
bootp_packet
{
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t unused;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  unsigned char chaddr[16];
  char sname[64];
  char file[128];
  char vend[64];
};