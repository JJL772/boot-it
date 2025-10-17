//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Minimal CFG file parser for C/C++
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
#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CFG_MAX_NAME_LEN 256

typedef struct cfg_val
{
  char* name;
  char* value;
  
  struct cfg_val* next;
} cfg_val_t;

typedef struct cfg_section
{
  char* name;
  struct cfg_val* values;
  
  struct cfg_section* next;
} cfg_section_t;

typedef struct cfg_file
{
  struct cfg_section* root;
} cfg_file_t;

static void
cfg__skip_ws(const char** p)
{
  while (**p) {
    char c = **p;
    if (!isspace(c)) {
      if (c != '#') break;       /* valid token */
      while (**p && **p != '\n') /* skip until end of line for comments */
        (*p)++;
      continue;                  /* consume yet more ws (if avail) */
    }
    (*p)++;
  }
}

static inline void
cfg__read_until(const char** p, char* ob, size_t ol, char delim)
{
  char* end = ob + ol - 1;
  while (**p && **p != delim && (delim == 0 ? !isspace(**p) : 1)) {
    if (ob >= end) { /* if overflowed, eat the rest */
      ++p;
      continue;
    }
    *ob = **p;
    ob++, (*p)++;
  }
  *ob = 0;
}

static inline ssize_t
cfg__estimate_strlen(const char* p, char delim)
{
  const char* op = p;
  while (*p && *p != delim && (delim == 0 ? !isspace(*p) : 1))
    ++p;
  return p - op;
}

static cfg_section_t*
cfg_new_section(const char* name, cfg_section_t* prev)
{
  cfg_section_t* ns = (cfg_section_t*)calloc(sizeof(cfg_section_t), 1);
  ns->name = strdup(name);
  if (prev) {
    ns->next = prev->next;
    prev->next = ns;
  }
  return ns;
}

static void
cfg__add_val(cfg_section_t* section, const char* name, char* val)
{
  cfg_val_t* pv = section->values, *nv = NULL;
  if (pv) {
    for (; pv->next; pv = pv->next)
      ;
  }
  
  nv = (cfg_val_t*)malloc(sizeof(cfg_val_t));
  nv->name = strdup(name);
  nv->value = val;
  nv->next = NULL;
  
  if (pv)
    pv->next = nv;
  else
    section->values = nv;
}

/**
 * Frees a cfg file in totality
 */
static void
cfg_free(cfg_file_t* file)
{
  for (cfg_section_t* s = file->root; s;) {
    for (cfg_val_t* v = s->values; v;) {
      cfg_val_t* nv = v->next;
      free(v->name);
      free(v->value);
      free(v);
      v = nv;
    }
    
    cfg_section_t* ns = s->next;
    free(s->name);
    free(s);
    s = ns;
  }
  
  free(file);
}

/**
 * Dump the cfg file to stdout. Mostly for debugging
 */
static void
cfg_dump(cfg_file_t* file)
{
  for (cfg_section_t* s = file->root; s; s = s->next) {
    if (s->name)
      printf("[%s]\n", s->name);
    for (cfg_val_t* v = s->values; v; v = v->next) {
      printf("%s = \"%s\"\n", v->name, v->value);
    }
  }
}

/**
 * Parse a cfg file from memory
 * \param data NULL terminated buffer of data
 * \param error Error callback function
 */
static struct cfg_file*
cfg_parse(const char* data, void(*error)(const char*))
{
  cfg_file_t* f = (cfg_file_t*)calloc(sizeof(cfg_file_t), 1);
  f->root = (cfg_section_t*)calloc(sizeof(cfg_section_t), 1);
  
  cfg_section_t* cur = f->root;
  
  const char* p = data;
  while (*p) {
    cfg__skip_ws(&p);
    if (*p == 0) break;                          /* check for EOF */
    if (*p == '[') {                             /* beginning of a section */
      ++p;                                       /* skip [ */
      char sn[CFG_MAX_NAME_LEN];
      cfg__skip_ws(&p);                          /* skip leading ws in brackets */
      cfg__read_until(&p, sn, sizeof(sn), ']');  /* read until ] */
      ++p;                                       /* skip ] */
      cur = cfg_new_section(sn, cur);            /* alloc new section and link it in */
      continue;
    }
    
    char vn[CFG_MAX_NAME_LEN];

    char delim = *p == '"' ? '"' : 0;           /* either read till quote or whitespace */
    cfg__read_until(&p, vn, sizeof(vn), delim); /* read it */

    cfg__skip_ws(&p);
    if (*p != '=') {                            /* we expect '=' here */
      char err[128];
      snprintf(err, sizeof(err), "expected '=' got '%c'", *p);
      error(err);
      goto error;
    }
    ++p;                                        /* skip = */
    cfg__skip_ws(&p);

    delim = *p == '"' ? '"' : 0;                /* either read till quote or whitespace */
    if (*p == '"') ++p;                         /* skip leading quote... */
    ssize_t l = cfg__estimate_strlen(p, delim); /* figure out buf size */
    char* buf = (char*)calloc(l + 1, 1);
    
    cfg__read_until(&p, buf, l+1, delim);       /* read it for real */
    cfg__add_val(cur, vn, buf);                 /* add the value */
    
    if (*p == '"') ++p;                         /* skip trailing quote if any */
  }
  
  return f;
error:
  cfg_free(f);
  return NULL;
}

#ifdef __cplusplus
}
#endif