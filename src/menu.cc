//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Keyboard menu (when in TTY mode)
//-----------------------------------------------------------------------------------------
// This file is part of 'boot-it'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'boot-it', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//-----------------------------------------------------------------------------------------

#include <stdio.h>
#include <termios.h>
#include <stdlib.h>
#include <unistd.h>

#include "bootpd.h"

typedef void (*menu_callback_t)();

/* Init the menu.
 * Configures stdin for immediate input w/o echo
 */
static void
menu_init()
{
  bool tty = isatty(STDIN_FILENO);

  /* configure stdin for key presses, if we're a tty */
  if (tty) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &t) >= 0) {
      t.c_lflag &= ~ICANON; /* disable canonical mode, get chars immediately */
      t.c_lflag &= ~ECHO;   /* disable input echo */
      if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0)
        perror("tcsetattr");
    }
    else {
      perror("tcgetattr");
    }
  }
}

[[noreturn]] static void
menu_run_noop()
{
  /* Do nothing */
  while (1) {
    sleep(10);
  }
}

[[noreturn]] static void
menu_run_norm(bootpd_ctx_t* bpc)
{
  bool paused = false;

  while (1) {
    /* input handling for tty */
    int c = getchar();
    switch (c) {
    case 'h':
      break;
    case 'p': /* pause/unpause */
      paused = !paused;
      bootpd_pause(bpc, paused);
      printf("BOOTP %s\n", paused ? "paused" : "unpaused");
      break;
    }
    usleep(1000);
  }
}

void
menu_run(bootpd_ctx_t* ctx)
{
  menu_init();

  if (isatty(STDIN_FILENO))
    menu_run_norm(ctx);
  else
    menu_run_noop();
}