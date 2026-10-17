#include "net_tools.h"
#include "terminal.h"
#include "config.h"
#include <WiFi.h>
#include <ping_sock.h>

static volatile bool s_pingBusy = false;
static volatile uint16_t s_pingSent = 0, s_pingRecv = 0;
static volatile uint32_t s_pingSum = 0;

static volatile bool s_hdBusy = false;
static HostRec s_hosts[64];
static volatile uint16_t s_hostCount = 0;

static volatile bool s_psBusy = false;
static uint16_t s_psFrom = 0, s_psTo = 0, s_psCur = 0;
static uint16_t s_psOpen[64];
static volatile uint16_t s_psOpenCount = 0;
static char s_psIP[16] = "";

void netInit() {}
bool uplinkConnected() { return WiFi.status() == WL_CONNECTED; }
String uplinkIP() { return WiFi.localIP().toString(); }

/* ---------------- PING ---------------- */
static void pingCb(esp_ping_handle_t h, void* args) {
  uint8_t type = 0;
  esp_ping_get_profile(h, ESP_PING_PROF_TYPE, &type, sizeof(type));
  if (type == ESP_PING_PROF_REPLY) {
    uint32_t t = 0;
    esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &t, sizeof(t));
    s_pingRecv++; s_pingSum += t;
    termLog(LVL_OK, "Ping reply %lums", (unsigned long)t);
  }
}

void pingStart(const char* host, uint8_t count) {
  if (s_pingBusy) return;
  if (!uplinkConnected()) { termLog(LVL_ERR, "Ping: no uplink network."); return; }
  s_pingBusy = true; s_pingSent = count; s_pingRecv = 0; s_pingSum = 0;

  ip_addr_t target;
  esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
  cfg.count = count;
  cfg.timeout_ms = 1000;
  cfg.interval_ms = 300;
  if (!ipaddr_aton(host, &target)) { termLog(LVL_ERR, "Bad host"); s_pingBusy = false; return; }
  cfg.target_addr = target;

  esp_ping_callbacks_t cbs = { .cb_args = nullptr, .on_ping_success = pingCb,
                               .on_ping_timeout = nullptr, .on_ping_end = nullptr };
  esp_ping_handle_t ph;
  esp_ping_new_session(&cfg, &cbs, &ph);
  esp_ping_start(ph);
  termLog(LVL_INFO, "Ping %s x%u", host, count);

  uint32_t t0 = millis();
  while (millis() - t0 < (uint32_t)count * 400 + 2000) { vTaskDelay(pdMS_TO_TICKS(50)); }
  esp_ping_stop(ph);
  esp_ping_delete_session(ph);
  s_pingBusy = false;
  termLog(LVL_OK, "Ping done: %u/%u replies", s_pingRecv, s_pingSent);
}

bool pingBusy()      { return s_pingBusy; }
uint16_t pingSent()  { return s_pingSent; }
uint16_t pingRecv()  { return s_pingRecv; }
float pingAvgMs()    { return s_pingRecv ? (float)s_pingSum / s_pingRecv : 0; }

/* ---------------- HOST DISCOVERY ---------------- */
void hostDiscoverStart() {
  if (s_hdBusy) return;
  s_hdBusy = true; s_hostCount = 0;
  IPAddress me = WiFi.localIP();
  if (me == IPAddress(0,0,0,0)) { termLog(LVL_ERR, "No uplink."); s_hdBusy = false; return; }

  termLog(LVL_INFO, "Host discovery on %u.%u.%u.0/24", me[0], me[1], me[2]);

  for (uint16_t h = 1; h < 255 && s_hostCount < 64; h++) {
    IPAddress t(me[0], me[1], me[2], h);
    WiFiClient c;
    uint32_t t0 = millis();
    if (c.connect(t, 80, 60) || c.connect(t, 443, 60) || c.connect(t, 22, 60)) {
      HostRec& r = s_hosts[s_hostCount++];
      memset(&r, 0, sizeof(r));
      memcpy(r.ip, &t, 4);
      r.ms = millis() - t0;
      r.alive = true;
      termLog(LVL_OK, "Host up: %s", t.toString().c_str());
    }
    c.stop();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  termLog(LVL_OK, "Discovery complete: %u hosts", s_hostCount);
  s_hdBusy = false;
}

void hostDiscoverStop() { s_hdBusy = false; }
bool hostDiscoverBusy() { return s_hdBusy; }
uint16_t hostCount() { return s_hostCount; }
bool hostGet(uint16_t i, HostRec* o) { if (i >= s_hostCount) return false; *o = s_hosts[i]; return true; }

/* ---------------- PORT SCAN ---------------- */
void portScanStart(const char* ip, uint16_t from, uint16_t to) {
  if (s_psBusy) return;
  strlcpy(s_psIP, ip, sizeof(s_psIP));
  s_psFrom = from; s_psTo = to; s_psCur = from;
  s_psOpenCount = 0; s_psBusy = true;
  termLog(LVL_INFO, "Port scan %s [%u-%u]", ip, from, to);
}

bool portScanBusy() { return s_psBusy; }
uint8_t portScanProgress() {
  if (!s_psBusy && !s_psTo) return 100;
  return (uint8_t)(((s_psCur - s_psFrom) * 100UL) / (s_psTo - s_psFrom + 1));
}
uint16_t portScanOpenCount() { return s_psOpenCount; }
uint16_t portScanOpen(uint16_t i) { return (i < s_psOpenCount) ? s_psOpen[i] : 0; }

/* ---------------- TICK ---------------- */
void netTick() {
  if (s_psBusy) {
    uint8_t done = 0;
    while (s_psCur <= s_psTo && done < 16) {
      WiFiClient c;
      IPAddress ip; ip.fromString(s_psIP);
      if (c.connect(ip, s_psCur, 120)) {
        if (s_psOpenCount < 64) s_psOpen[s_psOpenCount++] = s_psCur;
        termLog(LVL_OK, "  open: %u", s_psCur);
      }
      c.stop();
      s_psCur++; done++;
    }
    if (s_psCur > s_psTo) {
      s_psBusy = false;
      termLog(LVL_OK, "Port scan finished. %u open.", s_psOpenCount);
    }
  }
}