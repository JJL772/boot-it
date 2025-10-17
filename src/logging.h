//-----------------------------------------------------------------------------------------
// Copyright (C) 2025 Jeremy Lorelli
//-----------------------------------------------------------------------------------------
// Purpose: Simple logging subsystem
//-----------------------------------------------------------------------------------------
// This file is part of 'boot-it'. It is subject to the license terms in the
// LICENSE file found in the top-level directory of this distribution.
// No part of 'boot-it', including this file, may be copied, modified, propagated,
// or otherwise distributed except according to the terms contained in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//-----------------------------------------------------------------------------------------
#pragma once

#include <mutex>

extern std::mutex& logMutex();

void logErr(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void logMsg(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void logWarn(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

class LogScope final {
  std::mutex& mut;
public:
  LogScope() 
    : mut(logMutex())
  {
    mut.lock();
  }
  
  ~LogScope() { mut.unlock(); }
};