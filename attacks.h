#pragma once
#include "types.h"

void attacksInit();
void attacksTick();

/* deauther */
bool deauthStart(uint8_t mode, uint8_t type, uint16_t burst, uint32_t periodMs);
void deauthStop();
bool deauthActive();
uint32_t deauthSent();

/* beacon spam */
bool beaconStart(const char* prefix, uint8_t count);
void beaconStop();
bool beaconActive();

/* evil twin */
bool evilStart(const char* ssid, const char* pass, uint8_t ch);
void evilStop();
bool evilActive();
const char* evilSSID();

/* karma */
bool karmaStart();
void karmaStop();
bool karmaActive();
bool karmaAttack(uint16_t probeIndex);
uint16_t karmaClients();