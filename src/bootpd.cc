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
#include <atomic>

#include "bootpd.h"
#include "logging.h"

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
  std::atomic_bool paused;
};

static int bootpd__setup_socket(struct sockaddr_in* addr, const char* iface);
static int bootpd__init(struct bootpd_ctx* ctx);
static void* bootpd__thr_proc(void* p);
static int bootpd__run(struct bootpd_ctx* ctx);
static void bootpd__reply(struct bootpd_ctx* ctx, struct bootp_device* dev, struct bootp_packet* packet);
static int bootpd__mac2str(const unsigned char* mac, size_t macl, char* ob, size_t ol);
static bootp_device_t* bootpd__find_dev(struct bootpd_ctx* ctx, const char* mac);

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
  
  struct bootp_packet packet;
  struct sockaddr_in from;
  socklen_t addrlen = sizeof(from);
  while ((r = recvfrom(ctx->sock, &packet, sizeof(packet), 0, (struct sockaddr*)&from, &addrlen)) >= 0) {
    char mac[32];
    bootpd__mac2str(packet.chaddr, packet.hlen, mac, sizeof(mac));

    if (ctx->paused)
      continue; /* discard if paused */

    if (ctx->opts.verbose) {
      logMsg(
        "BOOTP XID 0x%08X; SECS %d; MAC %s\n",
        ntohl(packet.xid),
        ntohs(packet.secs),
        mac
      );
    }
    
    /* check if hostname is set & matches */
    if (*packet.sname && strcmp(packet.sname, ctx->hostname.c_str())) {
      if (ctx->opts.verbose) {
        logMsg(
          " --> Hostname '%s' != ours '%s'; discarding\n",
          packet.sname,
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

    bootpd__reply(ctx, cfg, &packet);

    if (ctx->opts.verbose)
      logMsg(" --> Replied\n");
  }
  return 0;
}

static void
bootpd__reply(struct bootpd_ctx* ctx, struct bootp_device* dev, struct bootp_packet* packet)
{
  struct bootp_packet newp = *packet;
  newp.op = BOOTP_OP_REPLY;
  if (!newp.ciaddr) /* assign IP if the client doesn't know theirs yet */
    newp.yiaddr = dev->ip;

  gethostname(newp.sname, sizeof(newp.sname)-1);

  /* our IP address */
  newp.siaddr = ctx->if_addr.sin_addr.s_addr;

  /* copy in file name */
  strncpy(newp.file, dev->file.data(), sizeof(newp.file));
  newp.file[sizeof(newp.file)-1] = 0;

  /* copy in vendor ext */
  strncpy(newp.vend, dev->vend.data(), sizeof(newp.vend));
  newp.vend[sizeof(newp.vend)-1] = 0;

  ssize_t r = 0;
  
  /* send it off */
  auto* sa = (struct sockaddr*)&ctx->if_baddr;
  if ((r = sendto(ctx->ssock, &newp, sizeof(newp), 0, sa, sizeof(ctx->if_baddr))) < 0) {
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

void
bootpd_pause(bootpd_ctx_t* c, int pause)
{
  c->paused = !!pause;
}