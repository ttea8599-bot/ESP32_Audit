#pragma once
#include <Arduino.h>

/* ---- 802.11 ---- */
struct __attribute__((packed)) MacHdr {
  uint16_t fc;
  uint16_t dur;
  uint8_t  a1[6];
  uint8_t  a2[6];
  uint8_t  a3[6];
  uint16_t seq;
};

struct RawPkt {
  int8_t   rssi;
  uint8_t  ch;
  uint16_t len;
  uint8_t  data[RAWQ_LEN];
};

struct PacketRec {
  uint32_t ts;
  int8_t   rssi;
  uint8_t  ch;
  uint8_t  type;
  uint8_t  subtype;
  uint8_t  src[6];
  uint8_t  dst[6];
  uint16_t len;
  char     info[96];
};

struct APInfo {
  char     ssid[33];
  uint8_t  bssid[6];
  int8_t   rssi;
  uint8_t  ch;
  uint8_t  auth;      // 0 open, 1 WEP, 2 WPA, 3 WPA2, 4 WPA/WPA2, 5 WPA3
  bool     hidden;
  bool     wps;
  uint32_t last;
};

struct ClientInfo {
  uint8_t  mac[6];
  uint8_t  bssid[6];
  char     ssid[33];
  int8_t   rssi;
  uint8_t  ch;
  uint32_t last;
};

struct ProbeInfo {
  uint8_t  mac[6];
  char     ssid[33];
  int8_t   rssi;
  uint8_t  ch;
  uint32_t last;
};

struct CredInfo {
  char     user[48];
  char     pass[64];
  char     ssid[33];
  uint32_t ts;
};

struct TargetInfo {
  bool     set;
  uint8_t  bssid[6];
  char     ssid[33];
  uint8_t  ch;
  int8_t   rssi;
  uint8_t  auth;
};

struct HostRec {
  uint8_t  ip[4];
  uint8_t  mac[6];
  uint16_t ms;
  bool     alive;
};

enum LogLevel { LVL_INFO, LVL_OK, LVL_WARN, LVL_ERR, LVL_TX };

struct LogLine {
  uint32_t ts;
  uint8_t  lvl;
  char     msg[112];
};