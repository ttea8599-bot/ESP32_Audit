#pragma once
#include "types.h"

void     storageInit();
void     storageTick();
bool     sdReady();
uint32_t sdFreeMB();
bool     credsAdd(const char* user, const char* pass, const char* ssid);
uint16_t credsCount();
bool     credsGet(uint16_t i, CredInfo* out);
void     credsClear();
void     credsLoadFromSD();
int16_t  hsSave(const uint8_t* data, uint16_t len, const char* ssid);
uint16_t hsCount();
const char* hsName(uint16_t i);
String   fsListJSON(const char* dir);
bool     fsDelete(const char* path);
void     saveConfig();
void     loadConfig();