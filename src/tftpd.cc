//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Lightweight tftp daemon in C++
//-----------------------------------------------------------------------------------------
// This file is part of 'boot-it'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'boot-it', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//-----------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "tftpd.h"
#include "logging.h"

/*** Protocol Definitions ***/
#define TFTP_RRQ 1
#define TFTP_WRQ 2
#define TFTP_DATA 3
#define TFTP_ACK 4
#define TFTP_ERR 5

#define TFTP_ERR_ND 0
#define TFTP_ERR_ENOENT 1
#define TFTP_ERR_EACCESS 2
#define TFTP_ERR_ENOSPACE 3
#define TFTP_ERR_EBADTRANS 5 /* Unknown transfer ID */
#define TFTP_ERR_EEXISTS 6
#define TFTP_ERR_ENOUSER 7

#define UDP_MAX_PAYLOAD 65507
#define RETRY_PERIOD 0.5 /* Retry after 0.5s elapsed */
#define TIMEOUT_PERIOD 4 /* Die after 4s */

#define BLOCK_SIZE 512

/*** Protocol structures ***/

#pragma pack(1)
struct tftp_ack
{
  uint16_t op;
  uint16_t block;
};

struct tftp_data
{
  uint16_t op;
  uint16_t block;
  char data[];
};
#pragma pack()

/*** Forward decls ***/

typedef struct tftpd_state
{
  std::string file;
  int fd;
  struct sockaddr_in addr;
  uint16_t block;
  int acked;
  double lastsent;
  int done;
  int errored;
  int write;
  int connected;
} tftpd_state_t;

int tftpd(const tftpd_opts_t *opts);
static void _send_error_resp(
  int fd,
  struct sockaddr_in *dst,
  socklen_t socklen,
  uint16_t errcode,
  const char *msg
);
static void tftpd__send_ack(
  int fd,
  struct sockaddr_in *dst,
  socklen_t socklen,
  uint16_t block
);
static double _curtime();

static int tftpd__init(tftpd_ctx_t* ctx, const tftpd_opts_t* opts);
static int tftpd__run(tftpd_ctx_t* ctx);
static void* tftpd__thread_proc(void* p);
static std::string tftpd__find_file(tftpd_ctx_t* ctx, const char* file);
static void tftpd__send_data(tftpd_ctx_t* ctx, tftpd_state_t* client, int block);

struct tftpd_ctx
{
  int sock;
  std::vector<tftpd_state> clients;

  pthread_attr_t thrattr;
  pthread_t thr;
  int run;
  
  tftpd_opts_t opts;
};

tftpd_ctx_t*
tftpd_start(const tftpd_opts_t *opts)
{
  auto* c = (tftpd_ctx_t*)calloc(sizeof(tftpd_ctx_t), 1);
  c->opts = *opts;
  c->run = 1;
  if (tftpd__init(c, opts) != 0) {
    free(c);
    return nullptr;
  }
  
  pthread_attr_init(&c->thrattr);
  pthread_create(&c->thr, &c->thrattr, tftpd__thread_proc, c);
  
  return c;
}

static void*
tftpd__thread_proc(void* p)
{
  tftpd__run((tftpd_ctx_t*)p);
  return nullptr;
}

static int
tftpd__init(tftpd_ctx_t* ctx, const tftpd_opts_t* opts)
{
  fprintf(stderr, "Started tftpd on %s:%d\n", opts->addr, opts->port);
  ctx->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (ctx->sock < 0) {
    perror("Unable to create socket");
    return -1;
  }

  struct sockaddr_in sa = {0};
  sa.sin_port = htons(opts->port);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(opts->addr);
  if (bind(ctx->sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    perror("Unable to bind address");
    close(ctx->sock);
    return -1;
  }

  /* Make it non-blocking */
  struct timeval tv = {0, 0};
  if (setsockopt(ctx->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setsockopt(SO_RECVTIMEO)");
    close(ctx->sock);
    return -1;
  }

  return 0;
}

void
tftpd_stop(tftpd_ctx_t* ctx)
{
  ctx->run = 0;
}

static int
compare_addrs(const struct sockaddr_in& l, const struct sockaddr_in& r)
{
  return l.sin_addr.s_addr == r.sin_addr.s_addr &&
    l.sin_port == r.sin_port &&
    l.sin_family == r.sin_family;
}

static struct tftpd_state*
find_or_add_client(tftpd_ctx_t* c, struct sockaddr_in* addr)
{
  for (auto &e : c->clients) {
    if (compare_addrs(e.addr, *addr))
      return &e;
  }

  c->clients.push_back({
    .addr = *addr,
  });
  return &c->clients[c->clients.size()-1];
}

static int
tftpd__run(tftpd_ctx_t* ctx)
{

  struct sockaddr_in fromaddr = {0};
  socklen_t fromsize = sizeof(fromaddr);

  /* Alloc working buf for an entire UDP packet */
  char buf[65535];

  ssize_t r;
  while (ctx->run) {
    /*************** Service incoming requests ***************/
    if ((r = recvfrom(ctx->sock, buf, sizeof(buf), 0, (struct sockaddr *)&fromaddr, &fromsize)) >= 0) {
      uint16_t op = ntohs(*(uint16_t *)buf);
      ssize_t rem = r;

      /* Match a client from the list, or create a new one */
      struct tftpd_state *client = find_or_add_client(ctx, &fromaddr);

      switch (op) {
      case TFTP_RRQ:
      case TFTP_WRQ: {
        char fileName[PATH_MAX] = {0}, mode[32] = {0};
        if (rem < 4) {
          logErr("Short read/write request from %s\n", inet_ntoa(fromaddr.sin_addr));
          break;
        }

        /* Read file name */
        char *s = buf + 2;
        for (char *pf = fileName; *s && rem > 0; ++s, ++pf, --rem)
          *pf = *s;

        /* file mode */
        ++s;
        for (char *pm = mode; *s && pm - mode < sizeof(mode) && rem > 0;
             ++s, ++pm, --rem)
          *pm = *s;

        if (!strcasecmp(mode, "netascii"))
          ;
        else if (!strcasecmp(mode, "octet"))
          ;
        else {
          logErr(
            "Unsupported mode '%s' for file '%s' from %s\n",
            mode,
            fileName,
            inet_ntoa(fromaddr.sin_addr)
          );
          client->errored = 1;
          break;
        }

        std::string realPath = tftpd__find_file(ctx, fileName);

        /* Check access flags */
        struct stat st;
        if (realPath.empty() || stat(realPath.data(), &st) < 0) {
          if (errno == ENOENT || realPath.empty()) {
            if (op != TFTP_WRQ) {
              _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_ENOENT, "No such file");
              client->errored = 1;
              break;
            }
          } else {
            logErr("stat(%s) failed: %s\n", realPath.data(), strerror(errno));
            _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EACCESS, "Stat failed");
            client->errored = 1;
            break;
          }
        }
        /* Overwrites not allowed */
        else if (op == TFTP_WRQ) {
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EEXISTS, "File exists");
          client->errored = 1;
          break;
        }

        /* No O+R or O+RW without -u == no access */
        int rcheck = ctx->opts.uparms ? S_IRUSR : S_IROTH,
            wcheck = ctx->opts.uparms ? S_IWUSR : S_IWOTH;
        if (op == TFTP_RRQ && !(st.st_mode & rcheck)) {
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EACCESS, "Access denied");
          client->errored = 1;
          break;
        }

        /* close existing files */
        if (client->fd > 0)
          close(client->fd);

        client->file = realPath;
        client->file[sizeof(client->file) - 1] = 0;
        client->write = op == TFTP_WRQ;

        client->fd = open(realPath.data(), op == TFTP_WRQ ? (O_CREAT | O_WRONLY | O_TRUNC) : O_RDONLY);
        if (client->fd < 0) {
          const char* err = strerror(errno);
          logMsg("Unable to open '%s': %s\n", realPath.data(), err);
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_ENOENT, err);
          client->errored = 1;
          break;
        }

        /* Update permissions for the file. open(2) does not behave
         * consistently... */
        if (op == TFTP_WRQ && chmod(realPath.data(), 0664) < 0) {
          int se = errno;
          logErr("Unable to chmod '%s': %s\n", realPath.data(), strerror(se));
          /* we're gonna reject this and remove the file. Don't want any weird
           * files w/broken perms sitting around.. we may be running as root,
           * that makes this even more annoying! */
          if (unlink(realPath.data()) < 0) {
            logErr(
              "Unable to unlink '%s': %s\n You will have to delete this manually!\n",
              realPath.data(),
              strerror(errno)
            );
          }
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EACCESS, strerror(se));
          client->errored = 1;
          break;
        }
        
        /* Send initial data */
        if (op == TFTP_RRQ) {
          tftpd__send_data(ctx, client, 1);
        }
        else {
          tftpd__send_ack(ctx->sock, &fromaddr, fromsize, 0);
        }

        client->block = 1;
        client->lastsent = _curtime();
        client->connected = 1;

        logMsg("Open file %s, mode %s\n", fileName, mode);
        break;
      }
      case TFTP_DATA: {
        if (!client->connected) {
          logMsg(
            "Unexpected packet from unconnected client at %s; ignoring\n",
            inet_ntoa(fromaddr.sin_addr)
          );
          break;
        }

        if (!client->write) {
          logWarn("Asked to write, but configured for read-only\n");
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EACCESS, "Asked to write, but configured for read");
          client->errored = 1;
          break;
        }
        struct tftp_data *dat = (struct tftp_data *)buf;
        uint16_t block = ntohs(dat->block);

        /* seek based on block number */
        lseek(client->fd, (block - 1) * BLOCK_SIZE, SEEK_SET);

        ssize_t tow = rem - sizeof(struct tftp_data);
        if (write(client->fd, dat->data, tow) < 0) {
          perror("write failed");
          _send_error_resp(ctx->sock, &fromaddr, fromsize, TFTP_ERR_EBADTRANS, "Unable to write");
          client->errored = 1;
          break;
        }

        /* Transaction is most likely done */
        if (tow < BLOCK_SIZE) {
          client->done = 1;
        }

        tftpd__send_ack(ctx->sock, &fromaddr, fromsize, block);
        client->block++;
        client->lastsent = _curtime();
        break;
      }
      case TFTP_ACK: {
        struct tftp_ack *ack = (struct tftp_ack *)buf;
        if (ntohs(ack->block) == client->block)
          client->acked = 1;
        else {
          logWarn(
            "Acked block '%d' but client was expecting ack for '%d'\n",
            ntohs(ack->block),
            client->block
          );
          //client->errored = 1;
        }
        client->lastsent = _curtime();
        break;
      }
      case TFTP_ERR:
        break;
      default:
        logWarn("Unknown opcode %d from %s\n", (int)op, inet_ntoa(fromaddr.sin_addr));
        client->errored = 1;
        break;
      }
    }

    /*************** Service outgoing requests ***************/
    for (auto &s : ctx->clients) {
      /* skip r/o clients, or ones that aren't open */
      if (s.write || !s.connected)
        continue;

      /* If ack'ed, move to next block */
      if (s.acked) {
        s.block++;
        s.acked = 0;
      }
      /* Not ack'ed yet; wait until retry period exceeded for this client */
      else if ((_curtime() - s.lastsent) < RETRY_PERIOD) {
        continue;
      }

      tftpd__send_data(ctx, &s, s.block);
      s.lastsent = _curtime();
    }

    /*************** Cleanup clients ***************/
    for (auto s = ctx->clients.begin(); s != ctx->clients.end();) {
      /* close open files when we're done with them, or if we timeout */
      if ((s->done && s->acked) || s->errored ||
          (_curtime() - s->lastsent > TIMEOUT_PERIOD))
      {
        logWarn("Closed connection %s\n", inet_ntoa(s->addr.sin_addr));
        close(s->fd);
        s = ctx->clients.erase(s);
      }
      else
        ++s;
    }
  }

  return 0;
}

static std::string
tftpd__find_file(tftpd_ctx_t* ctx, const char* file)
{
  for (const auto& p : ctx->opts.paths) {
    char tryFind[PATH_MAX];
    snprintf(tryFind, sizeof(tryFind), "%s/%s", p.data(), file);
    
    struct stat st;
    if (stat(tryFind, &st) < 0)
      continue;
    return tryFind;
  }
  return "";
}


static void
_send_error_resp(
  int fd,
  struct sockaddr_in *dst,
  socklen_t socklen,
  uint16_t errcode,
  const char *msg
)
{
#pragma pack(1)
  union {
    struct {
      uint16_t op;
      uint16_t errcode;
      char str[];
    } packet;
    char rawbuf[4096];
  } x;
#pragma pack()

  x.packet.errcode = htons(errcode);
  x.packet.op = htons(TFTP_ERR);
  strncpy(x.packet.str, msg, sizeof(x.rawbuf) - sizeof(x.packet));

  if (sendto(fd, x.rawbuf, sizeof(x.packet) + strlen(msg) + 1, 0, (struct sockaddr *)dst, socklen) < 0) {
    LogScope ls;
    perror("Unable to send error response");
  }
}

static void
tftpd__send_ack(int fd, struct sockaddr_in *dst, socklen_t socklen, uint16_t block)
{
  struct tftp_ack a = {htons(TFTP_ACK), htons(block)};
  if (sendto(fd, &a, sizeof(a), 0, (struct sockaddr *)dst, socklen) < 0) {
    LogScope ls;
    perror("Unable to send ACK");
  }
}

static double
_curtime()
{
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec + (tp.tv_nsec / 1e9);
}

static void
tftpd__send_data(tftpd_ctx_t* ctx, tftpd_state_t* s, int block)
{
  char readBuf[sizeof(struct tftp_data) + BLOCK_SIZE];

  struct tftp_data *packet = (struct tftp_data *)readBuf;
  packet->op = htons(TFTP_DATA);
  packet->block = htons(s->block);

  /* Seek and read based on block number */
  lseek(s->fd, (s->block - 1) * BLOCK_SIZE, SEEK_SET);

  ssize_t nr = read(s->fd, &packet->data, BLOCK_SIZE);
  if (nr < 0) {
    logErr("Unable to read %s: %s\n", s->file.data(), strerror(errno));
  }

  /* No more data to read, mark as dead. we'll still need to send an
   * additional packet of 0 len to terminate the transfer */
  if (nr == 0) {
    s->done = 1;
  }

  ssize_t sz = sizeof(struct tftp_data) + nr;
  if (sendto(ctx->sock, packet, sz, 0, (struct sockaddr *)&s->addr, sizeof(s->addr)) != sz) {
    LogScope ls;
    perror("send");
  }

  s->lastsent = _curtime();
  s->acked = 0;
}