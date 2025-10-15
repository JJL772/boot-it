//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Simple path utils for C/C++
//-----------------------------------------------------------------------------------------
// This file is part of 'c-utils'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'c-utils', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: MIT
//-----------------------------------------------------------------------------------------
#pragma once

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
namespace path {
#endif

/**
 * \brief Collapse a path string, eliminating . and ..
 * \param in Input string, optionally NULL to just use out
 * \param out Output string (or a string that can be modified)
 * \param osz
 * \param epr Error past root
 */
static inline int
path_collapse(const char* in, char* out, size_t osz, int epr)
{
  if (in) {
    strncpy(out, in, osz);
    out[osz-1] = 0;
  }

  char* p;
  for (p = out; *p;) {
    /* collapse simple '.' */
    if (*p == '.' && (*(p+1) == '/' || !*(p+1))) {
      int nc = *(p+1) ? 2 : 1;            /* copy 2 chars if p+1 is path sep */
      char* pp = p, *const op = p;        /* store previous location */
      p += nc;
      while (*p)                          /* shift everything over */
        *(pp++) = *(p++);
      *pp = 0;                            /* ensure terminated */
      p = op;                             /* process copied chunk again */
    }
    /* collapse '..' */
    else if (*p == '.' && *(p+1) == '.' && (*(p+2) == '/' || !*(p+2))) {
      if (p == out && epr) {              /* if at start of string, we're done */
        goto error;
      }

      int nc = *(p+2) == '/' ? 3 : 2;     /* store pointer to next component */
      char *np = p + nc;

      if (p > out) --p;                   /* skip to the / delim */
      while (p >= out && *p == '/') --p;  /* skip past / */
      if (p <= out) {
        if (epr) goto error;
        p = out;
      }

      while (p >= out && *p != '/') --p;  /* skip preceeding component */
      if (p < out) p = out;

      char* const op = p;                 /* store pointer to chunk to process again */

      while (*np)                         /* shift everything over */
        *(p++) = *(np++);
      *p = 0;                             /* ensure terminated */
      p = op;                             /* process again at start of copied component */
    }
    /* skip to next component */
    else {
      while (*p && *p != '/')
        ++p;
      if (*p)
        ++p; /* point at next component */
    }
  }
  return 0;
error:
  if (p < out)
    p = out;
  return -1;
}

/**
 * \brief Normalize the slashes in a path, removing duplicates and optionally trailing
 * \param path Path to normalize
 * \param strip_trail Whether or not to trip trailing slashes 
 */
static inline void
path_normalize(char* path, int strip_trail)
{
  for (char* p = path; *p;) {
    if (*p == '/') {
      ++p;
      if (!*p) {
        if (strip_trail) {
          --p;
          *p = 0;
        }
        return;
      }
      char *op = p, *const oop = p;
      /* find next component */
      while (*p == '/' && *p)
        *(p++) = 0;
      /* copy in next component */
      while (*p)
        *(op++) = *(p++);
      *op = 0;
      if (*(p-1) == '/' && strip_trail)
        *(op-1) = 0;
      p = oop;
    }
    else p++;
  }
}

#ifdef __cplusplus
} // namespace path
#endif
