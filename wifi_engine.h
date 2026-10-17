#pragma once
#include "types.h"

void wifiEngineInit();
void wifiEngineTick();

/* sniffer */
bool snifferStart(uint8_t ch, bool hop, uint8_t ftype, uint8_t subtype, int8_t rssiMin);
void snifferStop();
void snifferPause(bool p);
bool snifferRunning();
void snifferClear();
void snifferSetChannel(uint8_t ch);
void snifferSetHop(bool on);
void snifferSetFilters(const char* src, const char* dst, const char* ssid, int8_t rssiMin);

/* scanner */
void scanStart(bool passive);
bool scanBusy();
uint16_t apCount();   bool apGet(uint16_t i, APInfo* out);
void apClear();
uint16_t clientCount(); bool clientGet(uint16_t i, ClientInfo* out);
uint16_t probeCount();  bool probeGet(uint16_t i, ProbeInfo* out);
void probeClear();

/* packets */
uint16_t pktCount();
bool     pktGet(uint16_t i, PacketRec* out);
uint32_t rxTotal();
uint32_t txTotal();
uint32_t txDropped();
uint32_t curPPS();

/* target */
void targetSet(const uint8_t* bssid, const char* ssid, uint8_t ch, int8_t rssi, uint8_t auth);
void targetClear();
TargetInfo* targetGet();

/* raw TX */
bool rawTx(const uint8_t* frame, uint16_t len);
void sendDeauth(const uint8_t* ap, const uint8_t* sta, uint8_t reason);
uint8_t curChannel();