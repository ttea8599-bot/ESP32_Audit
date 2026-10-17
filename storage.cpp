#include "storage.h"
#include "config.h"
#include "terminal.h"
#include <SPI.h>
#include <SD.h>
#include <LittleFS.h>

static bool     s_sd = false;
static CredInfo s_creds[MAX_CREDS];
static volatile uint16_t s_credCount = 0;
static SemaphoreHandle_t s_cMtx = nullptr;
static char     s_hsNames[MAX_HANDSHAKES][32];
static volatile uint16_t s_hsCount = 0;

/* ---------- tiny PCAP writer ---------- */
static void pcapHdr(uint8_t* b, uint32_t& n) {
  // global header, LINKTYPE_IEEE802_11 = 105
  uint32_t magic = 0xA1B2C3D4; memcpy(b + 0, &magic, 4);
  uint16_t v = 2, m = 4;       memcpy(b + 4, &v, 2); memcpy(b + 6, &m, 2);
  uint32_t z = 0, snap = 65535, net = 105;
  memcpy(b + 8, &z, 4); memcpy(b + 12, &z, 4);
  memcpy(b + 16, &snap, 4); memcpy(b + 20, &net, 4);
  n = 24;
}

void storageInit() {
  s_cMtx = xSemaphoreCreateMutex();

  if (USE_SD) {
    SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
    if (SD.begin(SD_CS, SPI, SD_FREQ)) {
      s_sd = true;
      if (!SD.exists(PATH_HS)) SD.mkdir(PATH_HS);
      termLog(LVL_OK, "SD card mounted. Free: %lu MB", sdFreeMB());
      credsLoadFromSD();
    } else {
      termLog(LVL_WARN, "SD card not found — logging to RAM only.");
    }
  }

  if (!LittleFS.begin(true)) {
    termLog(LVL_ERR, "LittleFS mount FAILED — run uploadfs!");
  } else {
    termLog(LVL_OK, "LittleFS mounted.");
  }
}

void storageTick() {}

bool     sdReady()   { return s_sd; }
uint32_t sdFreeMB()  { return s_sd ? (SD.totalBytes() - SD.usedBytes()) / 1048576UL : 0; }

/* ---------- credentials ---------- */
bool credsAdd(const char* user, const char* pass, const char* ssid) {
  if (!s_cMtx) return false;
  if (xSemaphoreTake(s_cMtx, pdMS_TO_TICKS(80))) {
    uint16_t i = s_credCount;
    if (i >= MAX_CREDS) { i = MAX_CREDS - 1; s_credCount = MAX_CREDS - 1; }
    CredInfo& c = s_creds[i];
    strlcpy(c.user, user ? user : "", sizeof(c.user));
    strlcpy(c.pass, pass ? pass : "", sizeof(c.pass));
    strlcpy(c.ssid, ssid ? ssid : "", sizeof(c.ssid));
    c.ts = millis();
    if (s_credCount < MAX_CREDS) s_credCount++;
    xSemaphoreGive(s_cMtx);

    if (s_sd) {
      File f = SD.open(PATH_CREDS, FILE_APPEND);
      if (f) {
        f.printf("%lu|%s|%s|%s\n", (unsigned long)(millis() / 1000),
                 c.ssid, c.user, c.pass);
        f.close();
      }
    }
    termLog(LVL_OK, "CRED captured [%s] %s : %s", c.ssid, c.user, c.pass);
    return true;
  }
  return false;
}

uint16_t credsCount() {
  uint16_t n = 0;
  if (s_cMtx && xSemaphoreTake(s_cMtx, pdMS_TO_TICKS(40))) { n = s_credCount; xSemaphoreGive(s_cMtx); }
  return n;
}

bool credsGet(uint16_t i, CredInfo* out) {
  bool ok = false;
  if (s_cMtx && xSemaphoreTake(s_cMtx, pdMS_TO_TICKS(40))) {
    if (i < s_credCount) { *out = s_creds[i]; ok = true; }
    xSemaphoreGive(s_cMtx);
  }
  return ok;
}

void credsClear() {
  if (s_cMtx && xSemaphoreTake(s_cMtx, pdMS_TO_TICKS(80))) {
    s_credCount = 0; xSemaphoreGive(s_cMtx);
  }
  if (s_sd && SD.exists(PATH_CREDS)) SD.remove(PATH_CREDS);
  termLog(LVL_INFO, "Credential store cleared.");
}

void credsLoadFromSD() {
  if (!s_sd || !SD.exists(PATH_CREDS)) return;
  File f = SD.open(PATH_CREDS, FILE_READ);
  if (!f) return;
  while (f.available() && s_credCount < MAX_CREDS) {
    String line = f.readStringUntil('\n');
    int a = line.indexOf('|');       if (a < 0) continue;
    int b = line.indexOf('|', a + 1); if (b < 0) continue;
    int c = line.indexOf('|', b + 1); if (c < 0) continue;
    CredInfo& k = s_creds[s_credCount];
    strlcpy(k.ssid, line.substring(a + 1, b).c_str(), sizeof(k.ssid));
    strlcpy(k.user, line.substring(b + 1, c).c_str(), sizeof(k.user));
    strlcpy(k.pass, line.substring(c + 1).c_str(), sizeof(k.pass));
    s_credCount++;
  }
  f.close();
  termLog(LVL_INFO, "Loaded %u stored credentials.", s_credCount);
}

/* ---------- handshakes ---------- */
int16_t hsSave(const uint8_t* data, uint16_t len, const char* ssid) {
  if (!s_sd) return -1;
  if (s_hsCount >= MAX_HANDSHAKES) return -1;
  char path[64];
  snprintf(path, sizeof(path), PATH_HS "/hs_%02u_%s.pcap",
           (unsigned)s_hsCount, (ssid && *ssid) ? ssid : "hidden");

  File f = SD.open(path, FILE_WRITE);
  if (!f) return -1;
  uint8_t gh[24]; uint32_t gn; pcapHdr(gh, gn);
  f.write(gh, gn);
  // record header
  uint8_t rh[16]; uint32_t ts = millis() / 1000, us = (millis() % 1000) * 1000;
  memcpy(rh + 0, &ts, 4); memcpy(rh + 4, &us, 4);
  memcpy(rh + 8, &len, 4); memcpy(rh + 12, &len, 4);
  f.write(rh, 16);
  f.write(data, len);
  f.close();

  strlcpy(s_hsNames[s_hsCount], path, sizeof(s_hsNames[0]));
  s_hsCount++;
  termLog(LVL_OK, "Handshake saved -> %s", path);
  return s_hsCount - 1;
}

uint16_t hsCount() { return s_hsCount; }
const char* hsName(uint16_t i) { return (i < s_hsCount) ? s_hsNames[i] : ""; }

/* ---------- fs helpers ---------- */
String fsListJSON(const char* dir) {
  String out = "[";
  File d = LittleFS.open(dir);
  if (d && d.isDirectory()) {
    File f = d.openNextFile();
    bool first = true;
    while (f) {
      if (!first) out += ",";
      first = false;
      out += "{\"n\":\"" + String(f.name()) + "\",\"s\":" + String(f.size()) + "}";
      f = d.openNextFile();
    }
  }
  out += "]";
  return out;
}

bool fsDelete(const char* path) {
  if (!LittleFS.exists(path)) return false;
  return LittleFS.remove(path);
}

void saveConfig() {
  File f = LittleFS.open("/config.json", FILE_WRITE);
  if (!f) return;
  f.printf("{\"ssid\":\"%s\",\"pass\":\"%s\",\"admin\":\"%s\"}\n",
           MGMT_SSID, MGMT_PASS, ADMIN_PASS);
  f.close();
}
void loadConfig() {}