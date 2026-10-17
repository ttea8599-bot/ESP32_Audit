#pragma once
#include <ESPAsyncWebServer.h>

void webInit();
void webTick();
void wsPush(const char* json);
void wsBroadcast(const char* json);
uint16_t wsClients();
bool portalActive();
void portalCredSubmit(const char* user, const char* pass);