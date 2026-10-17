#pragma once
#include "types.h"

void termInit();
void termLog(uint8_t lvl, const char* fmt, ...);
uint16_t termDrain(LogLine* out, uint16_t max);
uint16_t termPending();
const char* termTag(uint8_t lvl);