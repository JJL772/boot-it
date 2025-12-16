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
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <list>
#include <mutex>
#include <cstdarg>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>

#include "cfgparser.h"
#include "path-tools.h"

#include "tftpd.h"
#include "bootpd.h"
#include "logging.h"

int verbose = 0;

std::mutex&
logMutex()
{
  static std::mutex m;
  return m;
}

struct bootit_ctx
{
  bootpd_opts_t bootpd_opts;
  
  bool tftpd = false;
  tftpd_opts_t tftpd_opts;
};

static bool bootit__parse_cfg(struct bootit_ctx* ctx, const char* cfg);
static void bootit__show_help(const char* a0, int code);

int
main(int argc, char** argv)
{
  struct bootit_ctx ctx = {};
  int opt = -1;
  bool parsed_cfg = false;
  
  char config[PATH_MAX];

  while ((opt = getopt(argc, argv, "c:i:vh")) != -1) {
    switch (opt) {
    case 'c':
      if (!bootit__parse_cfg(&ctx, optarg))
        return -1;
      parsed_cfg = true;
      break;
    case 'i':
      ctx.bootpd_opts.interface = optarg;
      break;
    case 'v':
      ctx.bootpd_opts.verbose++;
      verbose++;
      break;
    case 'h':
      bootit__show_help(argv[0], 0);
      break;
    default:
      printf("unknown arg '%c'\n", opt);
      bootit__show_help(argv[0], 1);
      break;
    }
  }

  /* default to boot.cfg in the cwd */
  if (!parsed_cfg) {
    struct stat st;
    if (stat("boot.cfg", &st) < 0) {
      fprintf(stderr, "Could not load boot.cfg\n");
      return 1;
    }

    if (!bootit__parse_cfg(&ctx, "boot.cfg")) {
      fprintf(stderr, "Error while loading boot.cfg\n");
      return 1;
    }
  }

  if (ctx.bootpd_opts.interface.empty()) {
    fprintf(stderr, "Interface must be specified using -i\n");
    return 1;
  }

  bootpd_ctx_t* bpc = bootpd_start(&ctx.bootpd_opts);
  if (!bpc) {
    fprintf(stderr, "failed to start bootp server\n");
    return 1;
  }
  
  ctx.tftpd_opts.port = 69;
  ctx.tftpd_opts.uparms = 1;
  strcpy(ctx.tftpd_opts.addr, "0.0.0.0");

  if (ctx.tftpd) {
    tftpd_ctx_t* tfc = tftpd_start(&ctx.tftpd_opts);
    if (!tfc) {
      fprintf(stderr, "failed to start tftpd\n");
      abort(); /* FIXME: err handling */
    }
  }
  
  /* configure stdin for key presses */
  struct termios t;
  if (tcgetattr(STDIN_FILENO, &t) >= 0) {
    t.c_lflag &= ~ICANON;
    t.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0)
      perror("tcsetattr");
  }
  else
    perror("tcgetattr");

  bool paused = false;
  while (1) {
    int c = getchar();
    switch (c) {
    case 'p':
      paused = !paused;
      bootpd_pause(bpc, paused);
      printf("BOOTP %s\n", paused ? "paused" : "unpaused");
      break;
    }
    usleep(1000);
  }
}

static void
error_callback(const char* s)
{
  fprintf(stderr, "%s\n", s);
}

static bool
bootit__parse_cfg(struct bootit_ctx* ctx, const char* cfg)
{
  FILE* fp = fopen(cfg, "rb");
  if (!fp) {
    fprintf(stderr, "No such file '%s'\n", cfg);
    return false;
  }
  
  fseek(fp, 0, SEEK_END);
  size_t l = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  
  char* buf = (char*)calloc(l+1, 1);
  fread(buf, l, 1, fp);
  fclose(fp);
  
  cfg_file_t* f = cfg_parse(buf, error_callback);
  if (!f) {
    free(buf);
    return false;
  }
  
  /* determine directory where the config lives */
  char cfgdir[PATH_MAX];
  getcwd(cfgdir, sizeof(cfgdir));
  strncat(cfgdir, "/", sizeof(cfgdir)-1);
  strncat(cfgdir, cfg, sizeof(cfgdir)-1);
  char* ps = strrchr(cfgdir, '/'); /* strip filename component */
  if (ps) *ps = 0;
  else cfgdir[0] = 0;

  for (cfg_section_t* s = f->root; s; s = s->next) {
    if (!s->name) { /* root section gets special handling */
      for (cfg_val_t* v = s->values; v; v = v->next) {
        if (!strcmp(v->name, "iface")) {       /* iface key */
          if (!ctx->bootpd_opts.interface.empty())
            fprintf(stderr, "WARN: iface= key overrides previous definition\n");
          ctx->bootpd_opts.interface = v->value;
        }
        else if (!strcmp(v->name, "tftpd")) {  /* tftpd key */
          if (!strcmp(v->value, "true"))
            ctx->tftpd = true;
          else if (!strcmp(v->value, "false"))
            ctx->tftpd = false;
          else
            fprintf(stderr, "WARN: tftp= key expects 'true' or 'false'\n");
        }
        else if (!strcmp(v->name, "path")) {   /* tftpd search path */
          /* canonicalize path */
          char obuf[PATH_MAX], tmpbuf[PATH_MAX];
          snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s", cfgdir, v->value);
          path::path_collapse(tmpbuf, obuf, sizeof(obuf), 0);

          ctx->tftpd_opts.paths.push_back(obuf);
        }
      }
      
      continue;
    }
    
    /* device sections parsed below here */

    struct bootp_device dev;
    dev.mac = s->name;
    
    for (cfg_val_t* v = s->values; v; v = v->next) {
      if (!strcmp(v->name, "ip"))         /* ip addr key */
        dev.ip = v->value;
      else if (!strcmp(v->name, "file"))  /* boot file key */
        dev.file = v->value;
      else if (!strcmp(v->name, "vend"))  /* vend key */
        dev.vend = v->value;
      else
        fprintf(stderr, "WARN: Ignoring unknown key '%s'\n", v->name);
    }
    
    ctx->bootpd_opts.devs.push_back(dev);
  }

  free(buf);
  return true;
}

static void
bootit__show_help(const char* arg0, int code)
{
  fprintf(stderr, "USAGE: %s [-c CONFIG] [-i INTERFACE] [-v]\n", arg0);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, " -c CONFIG    - Set the configuration file to use\n");
  fprintf(stderr, " -i IFACE     - Bind to this specific network interface (ex: eth0)\n");
  fprintf(stderr, " -v           - Enable verbose mode\n");
  exit(code);
}

void
logErr(const char* fmt, ...)
{
  LogScope ls;
  
  va_list va;
  va_start(va, fmt);
  fprintf(stderr, "[ERR] ");
  vfprintf(stdout, fmt, va);
  va_end(va);
}

void
logMsg(const char* fmt, ...)
{
  if (!verbose)
    return;

  LogScope ls;
  
  va_list va;
  va_start(va, fmt);
  fprintf(stderr, "[INFO] ");
  vfprintf(stdout, fmt, va);
  va_end(va);
}

void
logWarn(const char* fmt, ...)
{
  LogScope ls;
  
  va_list va;
  va_start(va, fmt);
  fprintf(stderr, "[WARN] ");
  vfprintf(stdout, fmt, va);
  va_end(va);
}
