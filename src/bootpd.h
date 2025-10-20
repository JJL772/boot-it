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
#include <vector>

enum dhcp_opt_type {
  DHCP_TYPE_INVALID = 0,
  DHCP_TYPE_UINT8,
  DHCP_TYPE_UINT16,
  DHCP_TYPE_UINT32,
  DHCP_TYPE_IPV4,
  DHCP_TYPE_IPV4_A,
  DHCP_TYPE_STRING,
};

typedef struct dhcp_opt
{
  uint8_t id;
  std::string value;
} dhcp_opt_t;

typedef struct dhcp_opt_desc
{
  dhcp_opt_type type;
  std::string name;
} dhcp_opt_desc;

#define DHCP_MAX_OPTS 255

const std::array<dhcp_opt_desc, DHCP_MAX_OPTS>& valid_dhcp_opts();

typedef struct bootp_device
{
  std::string mac;
  std::string ip;
  std::string file;
  std::string vend;
  std::vector<dhcp_opt_t> dhcp_opts;
} bootp_device_t;

typedef struct bootpd_opts
{
  std::string interface;
  std::string hostname;

  int verbose;
  
  std::list<bootp_device> devs;
  std::vector<dhcp_opt_t> dhcp_opts;
} bootpd_opts_t;

typedef struct bootpd_ctx bootpd_ctx_t;

bootpd_ctx_t* bootpd_start(const bootpd_opts_t* opts);
void bootpd_stop(bootpd_ctx_t* c);

template<typename T>
inline T rdN(const char*& ptr)
{
  T i = *(T*)ptr;
  ptr++;
  return i;
}

template<typename T>
inline void wrN(char*& ptr, T v)
{
  *(T*)ptr = v;
  ptr += sizeof(T);
}

bool validate_dhcp_opt(const dhcp_opt_desc& desc, const char* value);

/*-------------------- Protocol Definitions --------------------*/

#define BOOTP_SERVER_PORT 67
#define BOOTP_CLIENT_PORT 68

#define BOOTP_OP_REQUEST 1
#define BOOTP_OP_REPLY 2

#define BOOTP_DHCP_MAGIC 0x63825363

#define DHCP_OPT_REQ_PARAM_LIST  55
#define DHCP_OPT_CLIENT_IDENT    61
#define DHCP_OPT_MSG_TYPE        53
#define DHCP_OPT_MAX_MSG_SZ      57

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
  char vend[];
};