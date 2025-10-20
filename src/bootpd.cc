//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Lightweight bootp daemon
//-----------------------------------------------------------------------------------------
// This file is part of 'boot-it'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'boot-it', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//-----------------------------------------------------------------------------------------

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <pthread.h>
#include <cassert>
#include <array>

#include "bootpd.h"
#include "logging.h"

#undef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))

struct bootpd_ctx
{
  int sock;
  int ssock;

  std::string hostname;

  struct sockaddr_in if_addr;
  struct sockaddr_in if_baddr;
  
  bootpd_opts_t opts;
  
  pthread_t thr;
  pthread_attr_t thrattr;
  int run;
};

static int bootpd__setup_socket(struct sockaddr_in* addr, const char* iface);
static int bootpd__init(struct bootpd_ctx* ctx);
static void* bootpd__thr_proc(void* p);
static int bootpd__run(struct bootpd_ctx* ctx);
static void bootpd__reply(struct bootpd_ctx* ctx, struct bootp_device* dev, const struct bootp_packet* packet, ssize_t pl);
static int bootpd__mac2str(const unsigned char* mac, size_t macl, char* ob, size_t ol);
static bootp_device_t* bootpd__find_dev(struct bootpd_ctx* ctx, const char* mac);
static dhcp_opt_t* bootpd__find_dhcp_opt(struct bootpd_ctx* ctx, bootp_device_t* dev, uint8_t opt);

bootpd_ctx_t*
bootpd_start(const bootpd_opts_t* opts)
{
  auto* ctx = new bootpd_ctx_t();
  ctx->opts = *opts;
  ctx->run = 1;
  
  if (bootpd__init(ctx) < 0) {
    delete ctx;
    return nullptr;
  }
  
  pthread_attr_init(&ctx->thrattr);
  if (pthread_create(&ctx->thr, &ctx->thrattr, bootpd__thr_proc, ctx) < 0) {
    perror("pthread_create"); /* FIXME: error handling and im lazy */
  }

  return ctx;
}

void
bootpd_stop(bootpd_ctx_t* c)
{
  c->run = 0;
}

static void*
bootpd__thr_proc(void* p)
{
  auto* b = (bootpd_ctx_t*)p;
  bootpd__run(b);
  return nullptr;
}

static int
bootpd__setup_socket(struct sockaddr_in* addr, const char* iface)
{
  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    perror("socket");
    return -1;
  }
  
  /* allow port reuse */
  int en = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &en, sizeof(en)) < 0) {
    perror("setsockopt(SO_REUSEPORT)");
    close(sock);
    return -1;
  }
  
  /* allow broadcast */
  if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &en, sizeof(en)) < 0) {
    perror("setsockopt(SO_BROADCAST)");
    close(sock);
    return -1;
  }

  /* bind to the address */
  if (bind(sock, (struct sockaddr*)addr, sizeof(*addr)) < 0) {
    perror("bind");
    close(sock);
    return -1;
  }

  /* bind to interface */
  int r = setsockopt(
    sock,
    SOL_SOCKET,
    SO_BINDTODEVICE, 
    iface,
    strlen(iface) + 1
  );

  if (r < 0) {
    perror("setsockopt(SO_BINDTO_DEVICE)");
    close(sock);
    return -1;
  }

  return sock;
}

static int
bootpd__init(struct bootpd_ctx* ctx)
{
  struct ifaddrs* ifs = nullptr;
  bool found = false;

  /* query our hostname */
  char buf[512];
  if (gethostname(buf, sizeof(buf)) < 0)
    perror("unable to query hostname");
  else
    ctx->hostname = buf;
  
  if (getifaddrs(&ifs) < 0) {
    perror("getifaddrs");
    return -1;
  }

  /* match requested interface name with IP */
  for (struct ifaddrs* i = ifs; i; i = i->ifa_next) {
    /* Skip non-broadcast */
    if (!(i->ifa_flags & IFF_BROADCAST))
      continue;
    /* skip interfaces that aren't up */
    if (!(i->ifa_flags & IFF_UP))
      continue;
    /* skip loopback */
    if (i->ifa_flags & IFF_LOOPBACK)
      continue;
    /* skip interfaces w/o ipv4 */
    if (i->ifa_addr->sa_family != AF_INET)
      continue;

    if (strcmp(i->ifa_name, ctx->opts.interface.data()))
      continue;

    memcpy(&ctx->if_addr, i->ifa_addr, sizeof(struct sockaddr_in));
    memcpy(&ctx->if_baddr, i->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in));
    found = true;
    break;
  }

  freeifaddrs(ifs);

  if (!found) {
    fprintf(stderr, "Unable to find interface '%s'\n", ctx->opts.interface.data());
    return -1;
  }
  
  /* listen socket */
  struct sockaddr_in any = {};
  any.sin_family = AF_INET;
  any.sin_addr.s_addr = INADDR_BROADCAST;
  any.sin_port = htons(BOOTP_SERVER_PORT);
  ctx->sock = bootpd__setup_socket(&any, ctx->opts.interface.c_str());
  if (ctx->sock < 0)
    return -1;
  
  /* send socket */
  ctx->if_baddr.sin_port = htons(BOOTP_CLIENT_PORT);
  ctx->ssock = bootpd__setup_socket(&any, ctx->opts.interface.c_str());
  if (ctx->ssock < 0) {
    close(ctx->sock);
    return -1;
  }

  return 0;
}

static int
bootpd__run(struct bootpd_ctx* ctx)
{
  ssize_t r;
  
  char buf[65535];
  struct sockaddr_in from;
  socklen_t addrlen = sizeof(from);
  while ((r = recvfrom(ctx->sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &addrlen)) >= 0) {
    struct bootp_packet* packet = (struct bootp_packet*)buf;
    
    char mac[32];
    bootpd__mac2str(packet->chaddr, packet->hlen, mac, sizeof(mac));

    if (ctx->opts.verbose) {
      logMsg(
        "BOOTP XID 0x%08X; SECS %d; MAC %s\n",
        ntohl(packet->xid),
        ntohs(packet->secs),
        mac
      );
    }
    
    /* check if hostname is set & matches */
    if (*packet->sname && strcmp(packet->sname, ctx->hostname.c_str())) {
      if (ctx->opts.verbose) {
        logMsg(
          " --> Hostname '%s' != ours '%s'; discarding\n",
          packet->sname,
          ctx->hostname.c_str()
        );
      }
    }

    /* find device, discard if we have no entry */
    auto* cfg = bootpd__find_dev(ctx, mac);
    if (!cfg) {
      if (ctx->opts.verbose) {
        logMsg(" --> No matching device; discarding\n");
      }
      continue;
    }

    bootpd__reply(ctx, cfg, packet, r);

    if (ctx->opts.verbose)
      logMsg(" --> Replied\n");
  }
  return 0;
}

static void
bootpd__serialize_opt(
  char*& p,
  const char* end,
  const dhcp_opt_t& opt
)
{
  const auto& desc = valid_dhcp_opts()[opt.id];

  wrN<uint8_t>(p, opt.id);

  switch (desc.type) {
  case DHCP_TYPE_STRING: {
    wrN<uint8_t>(p, opt.value.size());
    for (int i = 0; i < opt.value.size(); ++i)
      *(p++) = opt.value[i];
    break;
  }
  case DHCP_TYPE_UINT8:
  case DHCP_TYPE_UINT32:
  case DHCP_TYPE_UINT16: {
    int base = 10;
    if (!strcmp(opt.value.c_str(), "0x"))
      base = 16;

    auto l = strtoll(opt.value.c_str(), nullptr, base);
    
    if (desc.type == DHCP_TYPE_UINT8) {
      wrN<uint8_t>(p, 1);
      wrN<uint8_t>(p, (uint8_t)l);
    }
    else if (desc.type == DHCP_TYPE_UINT16) {
      wrN<uint8_t>(p, 2);
      wrN<uint16_t>(p, (uint16_t)l);
    }
    else if (desc.type == DHCP_TYPE_UINT32) {
      wrN<uint8_t>(p, 4);
      wrN<uint32_t>(p, (uint32_t)l);
    }
    break;
  }
  case DHCP_TYPE_IPV4: {
    wrN<uint8_t>(p, 4); /* IPV4, always 4 octets */
    wrN<uint32_t>(p, inet_addr(opt.value.c_str()));
    break;
  }
  case DHCP_TYPE_IPV4_A: {
    std::vector<uint32_t> addrs;
    const char* next = nullptr;
    const char* st = opt.value.c_str();
    /* build a list of IPs */
    while (*st) {
      next = strpbrk(st, " ;");
      char buf[128];
      if (!next)
        strncpy(buf, st, sizeof(buf));
      else
        strncpy(buf, st, MIN(sizeof(buf), end-st));
      buf[sizeof(buf)-1] = 0;
      addrs.push_back(inet_addr(opt.value.c_str()));
      if (!next) break;
      st = next + 1;
    }
    
    /* actually write em out now */
    wrN<uint8_t>(p, addrs.size()*4);
    for (auto ip : addrs)
      wrN<uint32_t>(p, ip);
  }
  default:
    assert(0);
  }
}

static ssize_t
bootpd__fill_dhcp(
  struct bootpd_ctx* ctx,
  struct bootp_device* dev,
  const struct bootp_packet* inpacket,
  ssize_t pl,
  struct bootp_packet* packet,
  ssize_t bl
)
{
  const char* p = packet->vend;
  const char* end = packet->vend + pl - offsetof(bootp_packet, vend);
  p += 4; /* skip DHCP magic */
  
  /* build list of requested options */
  std::vector<dhcp_opt_t> opts;
  while (1) {
    auto op = rdN<uint8_t>(p);
    if (op == 0xFF)
      break;

    auto len = rdN<uint8_t>(p);

    switch (op){ 
    case DHCP_OPT_REQ_PARAM_LIST: /* requested response parameters */
      /* each entry is 1 byte */
      for (int i = 0; i < len; ++i) {
        auto req = rdN<uint8_t>(p);
        
        if (auto dhcp_opt = bootpd__find_dhcp_opt(ctx, dev, req)) {
          logMsg("  DHCP (%d) --> %s\n", req, dhcp_opt->value.c_str());
          opts.push_back(*dhcp_opt);
        }
      }
      break;
    default:
      break;
    }
    
    p += len;
  }

  char* np = packet->vend;
  char* nend = packet->vend + bl - offsetof(bootp_packet, vend);

  /* write out DHCP magic */
  *(np++) = 63;
  *(np++) = 82;
  *(np++) = 53;
  *(np++) = 63;
  
  /* serialize parameters */
  for (auto& opt : opts) {
    bootpd__serialize_opt(np, nend, opt);
  }
  
  /* write end marker */
  wrN<uint8_t>(np, 0xFF);
  
  return (uintptr_t)np - (uintptr_t)packet;
}

static void
bootpd__reply(struct bootpd_ctx* ctx, struct bootp_device* dev, const struct bootp_packet* packet, ssize_t pl)
{
  char sendbuf[65535];
  ssize_t sendSize = sizeof(bootp_packet);

  struct bootp_packet* newp = (struct bootp_packet*)sendbuf;
  memcpy(newp, packet, sizeof(bootp_packet));

  newp->op = BOOTP_OP_REPLY;
  if (!newp->ciaddr) /* assign IP if the client doesn't know theirs yet */
    newp->yiaddr = inet_addr(dev->ip.data());

  gethostname(newp->sname, sizeof(newp->sname)-1);

  /* our IP address */
  newp->siaddr = ctx->if_addr.sin_addr.s_addr;

  /* copy in file name */
  strncpy(newp->file, dev->file.data(), sizeof(newp->file));
  newp->file[sizeof(newp->file)-1] = 0;

  /* check for DHCP magic */
  if (packet->vend[0] == 63 && packet->vend[1] == 82 && packet->vend[2] == 53 && packet->vend[3] == 63) {
    sendSize = bootpd__fill_dhcp(ctx, dev, packet, pl, newp, sizeof(sendbuf));
  }
  else {
    /* otherwise we can specify arbitrary vend */
    strncpy(newp->vend, dev->vend.data(), sizeof(sendbuf)-offsetof(bootp_packet, vend));
    newp->vend[sizeof(sendbuf)-offsetof(bootp_packet, vend)] = 0;

    sendSize = sizeof(bootp_packet) + dev->vend.size();
  }

  ssize_t r = 0;
  
  /* send it off */
  auto* sa = (struct sockaddr*)&ctx->if_baddr;
  if ((r = sendto(ctx->ssock, sendbuf, sendSize, 0, sa, sizeof(ctx->if_baddr))) < 0) {
    LogScope ls;
    perror("send");
  }
}

static int
bootpd__mac2str(const unsigned char* mac, size_t macl, char* ob, size_t ol)
{
  for (int i = 0; i < macl; ++i) {
    *ob = "0123456789ABCDEF"[(*mac >> 4) & 0xF];
    ob++;
    *ob = "0123456789ABCDEF"[*mac & 0xF];
    mac++, ob++;
    if (i != macl-1)
      *(ob++) = ':';
  }
  return 0;
}

static bootp_device_t*
bootpd__find_dev(struct bootpd_ctx* ctx, const char* mac)
{
  for (auto& dev : ctx->opts.devs) {
    if (!strcasecmp(dev.mac.data(), mac))
      return &dev;
  }
  return nullptr;
}

static dhcp_opt_t*
bootpd__find_dhcp_opt(struct bootpd_ctx* ctx, bootp_device_t* dev, uint8_t opt)
{
  /* check device specific options first */
  for (auto& o : dev->dhcp_opts)
    if (o.id == opt)
      return &o;

  /* check global opts */
  for (auto& o : ctx->opts.dhcp_opts)
    if (o.id == opt)
      return &o;

  return nullptr;
}

const std::array<dhcp_opt_desc, DHCP_MAX_OPTS>&
valid_dhcp_opts()
{
  static std::array<dhcp_opt_desc, DHCP_MAX_OPTS> o;
  static bool init = false;
  if (!init) {
    init = true;
    
    o[1]   = {DHCP_TYPE_IPV4,   "subnet-mask"};
    o[2]   = {DHCP_TYPE_UINT32, "time-offset"};
    o[3]   = {DHCP_TYPE_IPV4_A, "router"};
    o[4]   = {DHCP_TYPE_IPV4_A, "time-server"};
    o[5]   = {DHCP_TYPE_IPV4_A, "nameserver"};
    o[6]   = {DHCP_TYPE_IPV4_A, "dns"};
    o[7]   = {DHCP_TYPE_IPV4_A, "log-server"};
    o[8]   = {DHCP_TYPE_IPV4_A, "cookie-server"};
    o[12]  = {DHCP_TYPE_STRING, "host-name"};
    o[13]  = {DHCP_TYPE_UINT16, "bootfile-size"};
    o[15]  = {DHCP_TYPE_STRING, "domain"};
    o[17]  = {DHCP_TYPE_STRING, "root-path"};
    o[18]  = {DHCP_TYPE_STRING, "extensions-path"};
    o[40]  = {DHCP_TYPE_STRING, "nis-domain"};
    o[41]  = {DHCP_TYPE_IPV4_A, "nis-servers"};
    o[42]  = {DHCP_TYPE_IPV4_A, "ntp-servers"};
    o[43]  = {DHCP_TYPE_STRING, "vendor"};
    o[66]  = {DHCP_TYPE_STRING, "tftp-server"};
    o[67]  = {DHCP_TYPE_STRING, "bootfile"};
    o[129] = {DHCP_TYPE_STRING, "uarg"}; /* often used to pass args to RTEMS systems */
  }
  return o;
}

static bool
ip_valid(const char* start, const char* end)
{
  char buf[128];
  strncpy(buf, start, end-start);
  buf[127] = 0;
  struct in_addr ina;
  return inet_aton(buf, &ina) == 1;
}

bool
validate_dhcp_opt(const dhcp_opt_desc& desc, const char* value)
{
  switch (desc.type) {
  case DHCP_TYPE_STRING:
    return true; /* anything is valid... */
  case DHCP_TYPE_IPV4:
    return ip_valid(value, value + strlen(value));
  case DHCP_TYPE_IPV4_A: {
    const char* end = nullptr;
    while (*value) {
      end = strpbrk(value, " ;");
      if (!end)
        return ip_valid(value, value + strlen(value));
      if (!ip_valid(value, end))
        return false;
      value = end+1;
    }
  }
  case DHCP_TYPE_UINT16:
  case DHCP_TYPE_UINT8:
  case DHCP_TYPE_UINT32: {
    long long l = 0;
    errno = 0;
    int base = 10;
    if (strcmp(value, "0x"))  {
      base = 16;
      value += 2;
    }
    l = strtoll(value, nullptr, base);
    if (errno == EINVAL)
      return false;
    if (desc.type == DHCP_TYPE_UINT8)
      return l < 0xFF;
    if (desc.type == DHCP_TYPE_UINT16)
      return l < 0xFFFF;
    if (desc.type == DHCP_TYPE_UINT32)
      return l < 0xFFFFFFFF;
    break;
  }
  default:
    return false;
  }
  return true;
}