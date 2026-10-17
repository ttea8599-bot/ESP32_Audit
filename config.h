#pragma once
#include <Arduino.h>

/* ============ FIRMWARE IDENTITY ============ */
#define FW_NAME     "ESP32 AUDIT"
#define FW_VERSION  "2.1.0"
#define FW_BUILD    __DATE__ " " __TIME__

/* ============ FEATURE SWITCHES ============ */
#define USE_EMBEDDED_ASSETS true   // web files firmware-এর ভেতরে (আলাদা FS ফ্ল্যাশ লাগবে না)
#define USE_SD              false  // SD কার্ড নেই
#define ENABLE_BLE          true
#define ENABLE_NET_TOOLS    true
#define HS_KEEP_IN_RAM      true   // SD না থাকলে handshake RAM-এ রাখবে

/* ============ MANAGEMENT AP ============ */
#define MGMT_SSID     "ESP32-Audit"
#define MGMT_PASS     "audit1234"     // >= 8 char
#define MGMT_CHANNEL  1
#define ADMIN_PASS    "admin"         // web UI login — বদলে নিন
#define MGMT_HIDDEN   false
#define AP_MAX_CONN   8

/* ============ OPTIONAL UPLINK (evil twin internet) ============ */
#define UPLINK_SSID   ""
#define UPLINK_PASS   ""

/* ============ SD CARD (SPI) ============ */
#define SD_CS     5
#define SD_SCK    18
#define SD_MISO   19
#define SD_MOSI   23
#define SD_FREQ   20000000
#define PATH_CREDS "/creds.txt"
#define PATH_HS    "/handshakes"

/* ============ PINS ============ */
#define LED_PIN        2
#define LED_ACTIVE_LOW false
#define BTN_PIN        0

/* ============ BUFFER LIMITS ============ */
#define LOG_RING        160
#define MAX_PACKETS     600
#define MAX_APS         96
#define MAX_CLIENTS     128
#define MAX_PROBES      64
#define MAX_CREDS       64
#define MAX_HANDSHAKES  16
#define RAWQ_DEPTH      48
#define RAWQ_LEN        160
#define MAX_BLE_DEV     48

/* ============ TIMING ============ */
#define HOP_INTERVAL_MS   250
#define WS_PUSH_MS        1000
#define WS_PKT_BATCH      40
#define STA_RECONNECT_MS  8000
#define DEAUTH_BURST      6
#define DEAUTH_GAP_MS     14
#define BEACON_GAP_MS     120
#define KARMA_ROTATE_MS   3000

/* ============ DEFAULTS ============ */
#define DEF_RSSI_MIN   -95
#define DEF_FTYPE      0xFF     // 0xFF = all
#define DEF_SUBTYPE    0xFF

/* beacon spam SSID list */
#define SPAM_SSID_COUNT 6