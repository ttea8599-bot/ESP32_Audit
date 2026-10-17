#include "wifi_engine.h"
#include "config.h"
#include "terminal.h"
#include "storage.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>

static QueueHandle_t s_q = nullptr;
static TaskHandle_t  s_task = nullptr;

static PacketRec  s_pkts[MAX_PACKETS];
static volatile uint16_t s_pkHead = 0, s_pkCount = 0;
static SemaphoreHandle_t s_pkMtx = nullptr;

static APInfo     s_aps[MAX_APS];         static volatile uint16_t s_apCount = 0;
static ClientInfo s_cli[MAX_CLIENTS];     static volatile uint16_t s_cliCount = 0;
static ProbeInfo  s_prb[MAX_PROBES];      static volatile uint16_t s_prbCount = 0;

static volatile bool s_sniff = false, s_pause = false, s_hop = true, s_scanning = false;
static volatile uint8_t s_ch = MGMT_CHANNEL;
static volatile uint8_t s_ftype = DEF_FTYPE, s_subtype = DEF_SUBTYPE;
static volatile int8_t  s_rssiMin = DEF_RSSI_MIN;
static char s_fSrc[18] = "", s_fDst[18] = "", s_fSsid[33] = "";

static volatile uint32_t s_rx = 0, s_tx = 0, s_txDrop = 0;
static uint32_t s_ppsCnt = 0, s_ppsLast = 0, s_pps = 0;

static TargetInfo s_target = { false, {0}, "", 0, 0, 0 };
static uint32_t   s_lastHop = 0;
static uint8_t    s_eapolCount = 0;
static uint32_t   s_eapolLast = 0;
static uint8_t    s_lastHs[512];
static uint16_t   s_lastHsLen = 0;

/* ================= helpers ================= */
static const char* SUBTYPE_NAMES[16] = {
  "ASSOC-REQ","ASSOC-RESP","REASSOC-REQ","REASSOC-RESP","PROBE-REQ","PROBE-RESP",
  "TIMING-ADV","RESERVED","BEACON","ATIM","DISASSOC","AUTH","DEAUTH","ACTION",
  "ACTION-NOACK","RESERVED"
};

static void macToStr(const uint8_t* m, char* out) {
  sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}

static bool macEq(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

static bool isBroadcast(const uint8_t* m) {
  static const uint8_t bc[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  return macEq(m, bc);
}

/* ================= ISR sniffer ================= */
static void IRAM_ATTR snifferCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!s_sniff || s_pause) return;
  const wifi_promiscuous_pkt_t* p = (const wifi_promiscuous_pkt_t*)buf;
  uint16_t len = p->rx_ctrl.sig_len;
  if (len < 24 || len > RAWQ_LEN) len = (len > RAWQ_LEN) ? RAWQ_LEN : len;

  RawPkt r;
  r.rssi = p->rx_ctrl.rssi;
  r.ch   = p->rx_ctrl.channel;
  r.len  = len;
  memcpy(r.data, p->payload, len);

  BaseType_t hp = pdFALSE;
  xQueueSendFromISR(s_q, &r, &hp);
  portYIELD_FROM_ISR(hp);
}

/* ================= packet store ================= */
static void pushPacket(const PacketRec& p) {
  if (s_pkMtx && xSemaphoreTake(s_pkMtx, pdMS_TO_TICKS(15))) {
    s_pkts[s_pkHead] = p;
    s_pkHead = (s_pkHead + 1) % MAX_PACKETS;
    if (s_pkCount < MAX_PACKETS) s_pkCount++;
    xSemaphoreGive(s_pkMtx);
  }
}

/* ================= IE parsing ================= */
static const uint8_t* findIE(const uint8_t* ies, uint16_t len, uint8_t id, uint8_t* outLen) {
  uint16_t i = 0;
  while (i + 2 <= len) {
    uint8_t eid = ies[i], elen = ies[i + 1];
    if (i + 2 + elen > len) break;
    if (eid == id) { if (outLen) *outLen = elen; return &ies[i + 2]; }
    i += 2 + elen;
  }
  return nullptr;
}

static bool hasWPS(const uint8_t* ies, uint16_t len) {
  uint16_t i = 0;
  while (i + 2 <= len) {
    uint8_t eid = ies[i], elen = ies[i + 1];
    if (i + 2 + elen > len) break;
    if (eid == 0xDD && elen >= 4 && ies[i+2] == 0x00 && ies[i+3] == 0x50 &&
        ies[i+4] == 0xF2 && ies[i+5] == 0x04) return true;
    i += 2 + elen;
  }
  return false;
}

static uint8_t parseAuth(const uint8_t* ies, uint16_t len, uint16_t cap) {
  if (!(cap & 0x0010)) return 0;                 // no privacy bit => open
  bool wpa = false, rsn = false;
  uint16_t i = 0;
  while (i + 2 <= len) {
    uint8_t eid = ies[i], elen = ies[i + 1];
    if (i + 2 + elen > len) break;
    if (eid == 48) rsn = true;
    if (eid == 221 && elen >= 4 && ies[i+2] == 0x00 && ies[i+3] == 0x50 &&
        ies[i+4] == 0xF2 && ies[i+5] == 0x01) wpa = true;
    i += 2 + elen;
  }
  if (wpa && rsn) return 4;
  if (rsn) return 3;
  if (wpa) return 2;
  return 1;
}

static const char* authName(uint8_t a) {
  switch (a) {
    case 0: return "OPEN";
    case 1: return "WEP";
    case 2: return "WPA";
    case 3: return "WPA2";
    case 4: return "WPA, WPA2";
    case 5: return "WPA3";
    default: return "?";
  }
}

/* ================= tables ================= */
static void upsertAP(const uint8_t* bssid, const char* ssid, int8_t rssi,
                     uint8_t ch, uint8_t auth, bool hidden, bool wps) {
  for (uint16_t i = 0; i < s_apCount; i++) {
    if (macEq(s_aps[i].bssid, bssid)) {
      s_aps[i].rssi = rssi; s_aps[i].ch = ch; s_aps[i].last = millis();
      s_aps[i].auth = auth; s_aps[i].wps = wps;
      if (ssid && *ssid) { strlcpy(s_aps[i].ssid, ssid, 33); s_aps[i].hidden = false; }
      return;
    }
  }
  if (s_apCount >= MAX_APS) return;
  APInfo& a = s_aps[s_apCount++];
  memset(&a, 0, sizeof(a));
  memcpy(a.bssid, bssid, 6);
  strlcpy(a.ssid, (ssid && *ssid) ? ssid : "(hidden)", 33);
  a.rssi = rssi; a.ch = ch; a.auth = auth; a.hidden = hidden; a.wps = wps;
  a.last = millis();
}

static void upsertClient(const uint8_t* mac, const uint8_t* bssid, int8_t rssi, uint8_t ch) {
  for (uint16_t i = 0; i < s_cliCount; i++)
    if (macEq(s_cli[i].mac, mac)) { s_cli[i].rssi = rssi; s_cli[i].last = millis(); return; }
  if (s_cliCount >= MAX_CLIENTS) return;
  ClientInfo& c = s_cli[s_cliCount++];
  memcpy(c.mac, mac, 6);
  memcpy(c.bssid, bssid, 6);
  c.rssi = rssi; c.ch = ch; c.last = millis();
  for (uint16_t i = 0; i < s_apCount; i++)
    if (macEq(s_aps[i].bssid, bssid)) { strlcpy(c.ssid, s_aps[i].ssid, 33); break; }
}

static void upsertProbe(const uint8_t* mac, const char* ssid, int8_t rssi, uint8_t ch) {
  if (!ssid || !*ssid) return;
  for (uint16_t i = 0; i < s_prbCount; i++)
    if (macEq(s_prb[i].mac, mac) && !strcmp(s_prb[i].ssid, ssid)) {
      s_prb[i].rssi = rssi; s_prb[i].ch = ch; s_prb[i].last = millis(); return;
    }
  if (s_prbCount >= MAX_PROBES) return;
  ProbeInfo& p = s_prb[s_prbCount++];
  memcpy(p.mac, mac, 6);
  strlcpy(p.ssid, ssid, 33);
  p.rssi = rssi; p.ch = ch; p.last = millis();
}

/* ================= filter ================= */
static bool passesFilter(const PacketRec& p) {
  if (s_ftype != 0xFF && p.type != s_ftype) return false;
  if (s_subtype != 0xFF && p.subtype != s_subtype) return false;
  if (p.rssi < s_rssiMin) return false;
  if (s_fSrc[0]) { char m[18]; macToStr(p.src, m); if (strcasecmp(m, s_fSrc)) return false; }
  if (s_fDst[0]) { char m[18]; macToStr(p.dst, m); if (strcasecmp(m, s_fDst)) return false; }
  if (s_fSsid[0]) {
    char low[96], f[33]; strlcpy(low, p.info, sizeof(low)); strlcpy(f, s_fSsid, sizeof(f));
    for (char* q = low; *q; q++) *q = tolower(*q);
    for (char* q = f; *q; q++) *q = tolower(*q);
    if (!strstr(low, f)) return false;
  }
  return true;
}

/* ================= EAPOL / handshake ================= */
static void checkEAPOL(const uint8_t* d, uint16_t len, const uint8_t* src,
                       const uint8_t* dst, const uint8_t* bssid) {
  // LLC SNAP + EAPOL type 0x888E
  if (len < 36) return;
  const uint8_t* llc = d + 24;
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
  if (llc[6] != 0x88 || llc[7] != 0x8E) return;

  const uint8_t* eap = llc + 8;
  uint8_t eapType = eap[1];
  if (eapType != 3) return;                    // EAPOL-Key only

  uint16_t keyInfo = (eap[5] << 8) | eap[6];
  uint8_t msg = 0;
  if ((keyInfo & 0x0008) && (keyInfo & 0x0080)) msg = 3;
  else if ((keyInfo & 0x0008) && (keyInfo & 0x0100)) msg = 4;
  else if ((keyInfo & 0x0080)) msg = 1;
  else if ((keyInfo & 0x0100)) msg = 2;

  s_eapolCount++;
  s_eapolLast = millis();

  char sm[18], dm[18];
  macToStr(src, sm); macToStr(dst, dm);
  termLog(LVL_TX, "EAPOL M%u  %s -> %s", msg, sm, dm);

  if (msg == 2 || msg == 4) {
    // copy whole frame and store as handshake
    uint16_t cpy = len > sizeof(s_lastHs) ? sizeof(s_lastHs) : len;
    memcpy(s_lastHs, d, cpy); s_lastHsLen = cpy;
    char ssid[33] = "hidden";
    for (uint16_t i = 0; i < s_apCount; i++)
      if (macEq(s_aps[i].bssid, bssid)) { strlcpy(ssid, s_aps[i].ssid, 33); break; }
    hsSave(d, cpy, ssid);
  }
}

/* ================= main parser ================= */
static void processPacket(RawPkt& r) {
  s_rx++;
  s_ppsCnt++;

  const MacHdr* h = (const MacHdr*)r.data;
  uint8_t type = (r.data[0] >> 2) & 0x03;
  uint8_t sub  = (r.data[0] >> 4) & 0x0F;

  const uint8_t* dst = h->a1;
  const uint8_t* src = h->a2;
  const uint8_t* bss = h->a3;

  // drop our own injected frames
  if (type == 0 && sub == 8 && r.len > 36 && r.data[10] == 0x02) { /* softAP beacon */ }

  PacketRec p;
  memset(&p, 0, sizeof(p));
  p.ts = millis(); p.rssi = r.rssi; p.ch = r.ch; p.type = type; p.subtype = sub;
  p.len = r.len;
  memcpy(p.src, src, 6); memcpy(p.dst, dst, 6);

  if (type == 0) {                                    // ---- MANAGEMENT ----
    uint16_t cap = 0;
    const uint8_t* ies = nullptr; uint16_t iesLen = 0;

    if (sub == 8 || sub == 5) {                       // BEACON / PROBE-RESP
      cap = r.data[34] | (r.data[35] << 8);
      ies = r.data + 36; iesLen = (r.len > 36) ? r.len - 36 : 0;

      uint8_t sl = 0;
      const uint8_t* ss = findIE(ies, iesLen, 0, &sl);
      char ssid[33] = ""; 
      if (ss && sl) { uint8_t n = sl > 32 ? 32 : sl; memcpy(ssid, ss, n); ssid[n] = 0; }

      uint8_t ch = 0;
      const uint8_t* ds = findIE(ies, iesLen, 3, nullptr);
      if (ds) ch = *ds;

      uint8_t auth = parseAuth(ies, iesLen, cap);
      bool wps = hasWPS(ies, iesLen);

      upsertAP(bss, ssid, r.rssi, ch ? ch : r.ch, auth, ssid[0] == 0, wps);

      snprintf(p.info, sizeof(p.info), "SSID: %s | Ch:%u | Sec:%s | WPS:%s",
               ssid[0] ? ssid : "(hidden)", ch ? ch : r.ch, authName(auth),
               wps ? "yes" : "no");
      strlcpy((char*)p.info + 0, p.info, sizeof(p.info));
    }
    else if (sub == 4) {                              // PROBE-REQ
      ies = r.data + 24; iesLen = (r.len > 24) ? r.len - 24 : 0;
      uint8_t sl = 0;
      const uint8_t* ss = findIE(ies, iesLen, 0, &sl);
      char ssid[33] = "";
      if (ss && sl) { uint8_t n = sl > 32 ? 32 : sl; memcpy(ssid, ss, n); ssid[n] = 0; }
      upsertProbe(src, ssid, r.rssi, r.ch);
      snprintf(p.info, sizeof(p.info), "Probe for: %s", ssid[0] ? ssid : "(wildcard)");
    }
    else if (sub == 11 || sub == 12) {                // AUTH / DEAUTH
      uint16_t reason = (r.len >= 26) ? (r.data[24] | (r.data[25] << 8)) : 0;
      upsertClient(src, bss, r.rssi, r.ch);
      snprintf(p.info, sizeof(p.info), "%s reason=%u",
               (sub == 12) ? "Deauth" : "Auth", reason);
    }
    else if (sub == 0 || sub == 2) {                  // ASSOC-REQ
      upsertClient(src, bss, r.rssi, r.ch);
      snprintf(p.info, sizeof(p.info), "Assoc request");
    }
    else {
      snprintf(p.info, sizeof(p.info), "%s", SUBTYPE_NAMES[sub]);
    }
  }
  else if (type == 2) {                               // ---- DATA ----
    if (dst[0] != 0xFF || src[0] != 0xFF) upsertClient(src, bss, r.rssi, r.ch);
    checkEAPOL(r.data, r.len, src, dst, bss);
    snprintf(p.info, sizeof(p.info), "Data %s", isBroadcast(dst) ? "(bcast)" : "");
  }
  else {
    snprintf(p.info, sizeof(p.info), "%s", SUBTYPE_NAMES[sub]);
  }

  if (passesFilter(p)) pushPacket(p);
}

/* ================= sniffer task ================= */
static void snifferTask(void* arg) {
  RawPkt r;
  for (;;) {
    if (xQueueReceive(s_q, &r, pdMS_TO_TICKS(50)) == pdTRUE) {
      processPacket(r);
    }
  }
}

/* ================= API ================= */
void wifiEngineInit() {
  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(MGMT_SSID, MGMT_PASS, MGMT_CHANNEL, MGMT_HIDDEN);
  WiFi.setSleep(false);

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_promiscuous(false);

  s_q = xQueueCreate(RAWQ_DEPTH, sizeof(RawPkt));
  s_pkMtx = xSemaphoreCreateMutex();
  xTaskCreatePinnedToCore(snifferTask, "sniff", 4096, nullptr, 4, &s_task, 1);

  termLog(LVL_OK, "Management AP: %s  ->  http://%s", MGMT_SSID,
          WiFi.softAPIP().toString().c_str());

  if (strlen(UPLINK_SSID)) {
    WiFi.begin(UPLINK_SSID, UPLINK_PASS);
    termLog(LVL_INFO, "Connecting to uplink %s ...", UPLINK_SSID);
  }
}

bool rawTx(const uint8_t* frame, uint16_t len) {
  esp_err_t e = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
  if (e == ESP_OK) { s_tx++; return true; }
  s_txDrop++;
  return false;
}

void sendDeauth(const uint8_t* ap, const uint8_t* sta, uint8_t reason) {
  uint8_t f[26];
  f[0] = 0xC0; f[1] = 0x00;
  f[2] = 0x3A; f[3] = 0x01;
  memcpy(f + 4, sta, 6);
  memcpy(f + 10, ap, 6);
  memcpy(f + 16, ap, 6);
  f[22] = 0x00; f[23] = 0x00;
  f[24] = reason; f[25] = 0x00;
  rawTx(f, 26);
}

void snifferSetChannel(uint8_t ch) {
  if (ch < 1 || ch > 13) return;
  s_ch = ch;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

bool snifferStart(uint8_t ch, bool hop, uint8_t ftype, uint8_t subtype, int8_t rssiMin) {
  if (s_sniff) return false;
  s_hop = hop; s_ftype = ftype; s_subtype = subtype; s_rssiMin = rssiMin;
  if (!hop && ch >= 1 && ch <= 13) snifferSetChannel(ch);

  wifi_promiscuous_filter_t flt;
  flt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
  esp_wifi_set_promiscuous_filter(&flt);
  esp_wifi_set_promiscuous_rx_cb(snifferCb);
  esp_wifi_set_promiscuous(true);
  s_sniff = true; s_pause = false;

  termLog(LVL_OK, "Starting Sniffer: Ch=%u, Hop=%u, Type=%u, Sub=%u",
          ch, hop ? 1 : 0, ftype, subtype);
  return true;
}

void snifferStop() {
  if (!s_sniff) return;
  esp_wifi_set_promiscuous(false);
  s_sniff = false;
  termLog(LVL_WARN, "Packet Sniffer stopped.");
}

void snifferPause(bool p) { s_pause = p; }
bool snifferRunning()     { return s_sniff; }

void snifferClear() {
  if (s_pkMtx && xSemaphoreTake(s_pkMtx, pdMS_TO_TICKS(80))) {
    s_pkHead = 0; s_pkCount = 0;
    xSemaphoreGive(s_pkMtx);
  }
  termLog(LVL_INFO, "Packet buffer cleared.");
}

void snifferSetHop(bool on) { s_hop = on; }

void snifferSetFilters(const char* src, const char* dst, const char* ssid, int8_t rssiMin) {
  strlcpy(s_fSrc,  src  ? src  : "", sizeof(s_fSrc));
  strlcpy(s_fDst,  dst  ? dst  : "", sizeof(s_fDst));
  strlcpy(s_fSsid, ssid ? ssid : "", sizeof(s_fSsid));
  s_rssiMin = rssiMin;
}

void snifferClearFilters() { s_fSrc[0]=s_fDst[0]=s_fSsid[0]=0; s_rssiMin = DEF_RSSI_MIN; }

/* ---- scanner ---- */
void scanStart(bool passive) {
  if (s_scanning) return;
  s_scanning = true;
  termLog(LVL_INFO, "Starting WiFi Scan (WS)...");
  int n = WiFi.scanNetworks(false, true);
  if (n > 0) {
    for (int i = 0; i < n; i++) {
      uint8_t* b = WiFi.BSSID(i);
      upsertAP(b, WiFi.SSID(i).c_str(), WiFi.RSSI(i), WiFi.channel(i),
               (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? 0 : 3, false, false);
    }
    termLog(LVL_OK, "Scan complete. Found %d APs.", n);
  } else {
    termLog(LVL_WARN, "Scan complete. Found 0 APs.");
  }
  WiFi.scanDelete();
  s_scanning = false;
}

bool scanBusy() { return s_scanning; }

uint16_t apCount() { return s_apCount; }
bool apGet(uint16_t i, APInfo* o) { if (i >= s_apCount) return false; *o = s_aps[i]; return true; }
void apClear() { s_apCount = 0; }

uint16_t clientCount() { return s_cliCount; }
bool clientGet(uint16_t i, ClientInfo* o) { if (i >= s_cliCount) return false; *o = s_cli[i]; return true; }

uint16_t probeCount() { return s_prbCount; }
bool probeGet(uint16_t i, ProbeInfo* o) { if (i >= s_prbCount) return false; *o = s_prb[i]; return true; }
void probeClear() { s_prbCount = 0; }

uint16_t pktCount() {
  uint16_t n = 0;
  if (s_pkMtx && xSemaphoreTake(s_pkMtx, pdMS_TO_TICKS(30))) { n = s_pkCount; xSemaphoreGive(s_pkMtx); }
  return n;
}

bool pktGet(uint16_t idx, PacketRec* o) {
  bool ok = false;
  if (s_pkMtx && xSemaphoreTake(s_pkMtx, pdMS_TO_TICKS(30))) {
    if (idx < s_pkCount) {
      uint16_t pos = (s_pkHead + MAX_PACKETS - s_pkCount + idx) % MAX_PACKETS;
      *o = s_pkts[pos]; ok = true;
    }
    xSemaphoreGive(s_pkMtx);
  }
  return ok;
}

uint32_t rxTotal()    { return s_rx; }
uint32_t txTotal()    { return s_tx; }
uint32_t txDropped()  { return s_txDrop; }
uint32_t curPPS()     { return s_pps; }
uint8_t  curChannel() { return s_ch; }

void targetSet(const uint8_t* b, const char* s, uint8_t ch, int8_t r, uint8_t a) {
  memcpy(s_target.bssid, b, 6);
  strlcpy(s_target.ssid, s ? s : "", sizeof(s_target.ssid));
  s_target.ch = ch; s_target.rssi = r; s_target.auth = a; s_target.set = true;
  char m[18]; macToStr(b, m);
  termLog(LVL_OK, "TARGET locked: %s [%s] ch=%u", s_target.ssid, m, ch);
}
void targetClear() { s_target.set = false; termLog(LVL_INFO, "Target cleared."); }
TargetInfo* targetGet() { return &s_target; }

/* ---- tick ---- */
void wifiEngineTick() {
  uint32_t now = millis();

  if (s_sniff && s_hop && (now - s_lastHop > HOP_INTERVAL_MS)) {
    s_lastHop = now;
    uint8_t n = (s_ch % 13) + 1;
    snifferSetChannel(n);
  }

  if (now - s_ppsLast >= 1000) {
    s_pps = s_ppsCnt;
    s_ppsCnt = 0;
    s_ppsLast = now;
  }

  if (s_target.set) {
    for (uint16_t i = 0; i < s_apCount; i++)
      if (macEq(s_aps[i].bssid, s_target.bssid)) { s_target.rssi = s_aps[i].rssi; break; }
  }
}