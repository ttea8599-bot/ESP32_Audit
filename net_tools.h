#pragma once
#include "types.h"

void netInit();
void netTick();

/* ping */
void pingStart(const char* host, uint8_t count);
bool pingBusy();
uint16_t pingSent();
uint16_t pingRecv();
float    pingAvgMs();

/* host discovery */
void hostDiscoverStart();
void hostDiscoverStop();
bool hostDiscoverBusy();
uint16_t hostCount();
bool hostGet(uint16_t i, HostRec* out);

/* port scan */
void portScanStart(const char* ip, uint16_t from, uint16_t to);
bool portScanBusy();
uint8_t portScanProgress();
uint16_t portScanOpenCount();
uint16_t portScanOpen(uint16_t i);

/* sta */
bool uplinkConnected();
String uplinkIP();