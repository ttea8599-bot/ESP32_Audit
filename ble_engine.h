#pragma once
#include "types.h"

struct BLEDev {
  uint8_t  addr[6];
  int8_t   rssi;
  char     name[32];
  uint16_t company;
};

void  bleInit();
void  bleTick();
void  bleScanStart();
void  bleScanStop();
bool  bleScanning();
uint16_t bleCount();
bool  bleGet(uint16_t i, BLEDev* out);
void  bleClear();
void  bleSpamStart(uint8_t mode);
void  bleSpamStop();
bool  bleSpamming();