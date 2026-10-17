#include "terminal.h"
#include <stdarg.h>

static LogLine s_ring[LOG_RING];
static volatile uint16_t s_head = 0, s_tail = 0;
static SemaphoreHandle_t s_mtx = nullptr;

const char* termTag(uint8_t lvl) {
  switch (lvl) {
    case LVL_OK:   return "OK  ";
    case LVL_WARN: return "WARN";
    case LVL_ERR:  return "ERR ";
    case LVL_TX:   return "TX  ";
    default:       return "SYS ";
  }
}

void termInit() {
  if (!s_mtx) s_mtx = xSemaphoreCreateMutex();
}

void termLog(uint8_t lvl, const char* fmt, ...) {
  LogLine l;
  l.ts  = millis();
  l.lvl = lvl;
  va_list ap; va_start(ap, fmt);
  vsnprintf(l.msg, sizeof(l.msg), fmt, ap);
  va_end(ap);

  if (s_mtx && xSemaphoreTake(s_mtx, pdMS_TO_TICKS(25))) {
    uint16_t n = (s_head + 1) % LOG_RING;
    if (n != s_tail) { s_ring[s_head] = l; s_head = n; }
    else { s_tail = (s_tail + 1) % LOG_RING; s_ring[s_head] = l; s_head = n; }
    xSemaphoreGive(s_mtx);
  }
  Serial.printf("[%s] %s\n", termTag(lvl), l.msg);
}

uint16_t termPending() {
  return (s_head + LOG_RING - s_tail) % LOG_RING;
}

uint16_t termDrain(LogLine* out, uint16_t max) {
  uint16_t n = 0;
  if (!s_mtx) return 0;
  if (xSemaphoreTake(s_mtx, pdMS_TO_TICKS(25))) {
    while (n < max && s_tail != s_head) {
      out[n++] = s_ring[s_tail];
      s_tail = (s_tail + 1) % LOG_RING;
    }
    xSemaphoreGive(s_mtx);
  }
  return n;
}