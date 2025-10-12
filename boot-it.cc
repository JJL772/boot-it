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

#include "cfgparser.h"
#include "path-tools.h"

#include "tftpd.h"
#include "bootpd.h"

struct bootit_ctx
{
  bootpd_opts_t bootpd_opts;
  
  bool tftpd = false;
  tftpd_opts_t tftpd_opts;
};

static bool bootit__parse_cfg(struct bootit_ctx* ctx, const char* cfg);

int
main(int argc, char** argv)
{
  struct bootit_ctx ctx = {};
  int opt = -1;
  
  char config[PATH_MAX];

  while ((opt = getopt(argc, argv, "c:i:v")) != -1) {
    switch (opt) {
    case 'c':
      if (!bootit__parse_cfg(&ctx, optarg))
        return -1;
      break;
    case 'i':
      ctx.bootpd_opts.interface = optarg;
      break;
    case 'v':
      ctx.bootpd_opts.verbose++;
      break;
    default:
      printf("unknown arg '%c'\n", opt);
      exit(1);
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
  strcpy(ctx.tftpd_opts.addr, "10.0.0.1");

  if (ctx.tftpd) {
    tftpd_ctx_t* tfc = tftpd_start(&ctx.tftpd_opts);
    if (!tfc) {
      fprintf(stderr, "failed to start tftpd\n");
    }
    abort(); /* FIXME: err handling */
  }
  
  while (1) {
    sleep(1);
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
