#pragma once

#include "common.h"

namespace Log {
void Init();
void Init(const char* path);
void Shutdown();
void Write(const char* fmt, ...);
void Info(const char* fmt, ...);
void Warn(const char* fmt, ...);
void Error(const char* fmt, ...);
void Debug(const char* fmt, ...);
}

#define LOG(fmt, ...) Log::Write(fmt, ##__VA_ARGS__)
